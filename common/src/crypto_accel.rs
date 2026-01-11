//! Hardware-Accelerated Cryptography
//!
//! Uses AES-NI, AVX2, and ARM crypto extensions for maximum throughput.
//! Falls back to software implementations on unsupported hardware.
//!
//! Performance targets:
//! - AES-GCM with AES-NI: ~10 GB/s
//! - ChaCha20-Poly1305: ~3 GB/s
//! - Software AES: ~500 MB/s

use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::error::Unspecified;
use std::sync::atomic::{AtomicU64, Ordering};

/// Crypto algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoAlgorithm {
    /// AES-256-GCM (fastest with AES-NI)
    Aes256Gcm,
    /// ChaCha20-Poly1305 (fast without hardware AES)
    ChaCha20Poly1305,
}

impl CryptoAlgorithm {
    /// Select best algorithm based on hardware
    pub fn auto_select() -> Self {
        if Self::has_aes_ni() {
            CryptoAlgorithm::Aes256Gcm
        } else {
            CryptoAlgorithm::ChaCha20Poly1305
        }
    }

    /// Check if AES-NI is available
    #[cfg(target_arch = "x86_64")]
    pub fn has_aes_ni() -> bool {
        is_x86_feature_detected!("aes")
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn has_aes_ni() -> bool {
        false
    }

    /// Get AEAD algorithm for ring
    fn aead_algorithm(&self) -> &'static aead::Algorithm {
        match self {
            CryptoAlgorithm::Aes256Gcm => &aead::AES_256_GCM,
            CryptoAlgorithm::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    /// Get key length in bytes
    pub fn key_len(&self) -> usize {
        match self {
            CryptoAlgorithm::Aes256Gcm => 32,
            CryptoAlgorithm::ChaCha20Poly1305 => 32,
        }
    }

    /// Get nonce length in bytes
    pub fn nonce_len(&self) -> usize {
        12 // Both algorithms use 12-byte nonces
    }

    /// Get authentication tag length
    pub fn tag_len(&self) -> usize {
        16 // Both use 16-byte tags
    }

    /// Estimated throughput in MB/s
    pub fn estimated_throughput(&self) -> u32 {
        match self {
            CryptoAlgorithm::Aes256Gcm => {
                if Self::has_aes_ni() {
                    10000 // 10 GB/s with AES-NI
                } else {
                    500 // Software AES
                }
            }
            CryptoAlgorithm::ChaCha20Poly1305 => 3000, // ~3 GB/s
        }
    }
}

/// Counter-based nonce sequence for AEAD
#[allow(dead_code)]
struct CounterNonce {
    counter: AtomicU64,
    prefix: [u8; 4], // 4-byte prefix + 8-byte counter = 12-byte nonce
}

impl CounterNonce {
    #[allow(dead_code)]
    fn new(prefix: [u8; 4]) -> Self {
        CounterNonce {
            counter: AtomicU64::new(0),
            prefix,
        }
    }
}

impl NonceSequence for CounterNonce {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let counter = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.prefix);
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        Nonce::try_assume_unique_for_key(&nonce)
    }
}

/// High-performance crypto context
pub struct CryptoContext {
    algorithm: CryptoAlgorithm,
    key: Vec<u8>,
}

impl CryptoContext {
    /// Create a new crypto context with the specified algorithm
    pub fn new(algorithm: CryptoAlgorithm, key: &[u8]) -> Result<Self, CryptoError> {
        if key.len() != algorithm.key_len() {
            return Err(CryptoError::InvalidKeyLength);
        }

        Ok(CryptoContext {
            algorithm,
            key: key.to_vec(),
        })
    }

    /// Create with auto-selected algorithm
    pub fn auto(key: &[u8]) -> Result<Self, CryptoError> {
        Self::new(CryptoAlgorithm::auto_select(), key)
    }

    /// Get the algorithm
    pub fn algorithm(&self) -> CryptoAlgorithm {
        self.algorithm
    }

    /// Encrypt data in-place with authentication
    /// Returns the authentication tag
    pub fn encrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let unbound_key = UnboundKey::new(self.algorithm.aead_algorithm(), &self.key)
            .map_err(|_| CryptoError::KeyError)?;

        // Create a single-use nonce sequence
        let nonce_bytes: [u8; 12] = nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;

        struct SingleNonce([u8; 12]);
        impl NonceSequence for SingleNonce {
            fn advance(&mut self) -> Result<Nonce, Unspecified> {
                Nonce::try_assume_unique_for_key(&self.0)
            }
        }

        let mut sealing_key = SealingKey::new(unbound_key, SingleNonce(nonce_bytes));

        sealing_key
            .seal_in_place_append_tag(Aad::from(aad), data)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok(())
    }

    /// Decrypt data in-place with authentication verification
    pub fn decrypt_in_place(
        &self,
        nonce: &[u8],
        aad: &[u8],
        data: &mut Vec<u8>,
    ) -> Result<(), CryptoError> {
        let unbound_key = UnboundKey::new(self.algorithm.aead_algorithm(), &self.key)
            .map_err(|_| CryptoError::KeyError)?;

        let nonce_bytes: [u8; 12] = nonce.try_into().map_err(|_| CryptoError::InvalidNonce)?;

        struct SingleNonce([u8; 12]);
        impl NonceSequence for SingleNonce {
            fn advance(&mut self) -> Result<Nonce, Unspecified> {
                Nonce::try_assume_unique_for_key(&self.0)
            }
        }

        let mut opening_key = OpeningKey::new(unbound_key, SingleNonce(nonce_bytes));

        let plaintext = opening_key
            .open_in_place(Aad::from(aad), data)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        let len = plaintext.len();
        data.truncate(len);

        Ok(())
    }

    /// Encrypt data (returns ciphertext + tag)
    pub fn encrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut data = plaintext.to_vec();
        self.encrypt_in_place(nonce, aad, &mut data)?;
        Ok(data)
    }

    /// Decrypt data
    pub fn decrypt(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut data = ciphertext.to_vec();
        self.decrypt_in_place(nonce, aad, &mut data)?;
        Ok(data)
    }
}

/// Crypto errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidKeyLength,
    InvalidNonce,
    KeyError,
    EncryptionFailed,
    DecryptionFailed,
    AuthenticationFailed,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::InvalidNonce => write!(f, "Invalid nonce"),
            CryptoError::KeyError => write!(f, "Key error"),
            CryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            CryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            CryptoError::AuthenticationFailed => write!(f, "Authentication failed"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Batch encryption for high throughput
pub struct BatchCrypto {
    ctx: CryptoContext,
    nonce_counter: AtomicU64,
    nonce_prefix: [u8; 4],
}

impl BatchCrypto {
    pub fn new(
        algorithm: CryptoAlgorithm,
        key: &[u8],
        nonce_prefix: [u8; 4],
    ) -> Result<Self, CryptoError> {
        Ok(BatchCrypto {
            ctx: CryptoContext::new(algorithm, key)?,
            nonce_counter: AtomicU64::new(0),
            nonce_prefix,
        })
    }

    /// Generate next nonce
    fn next_nonce(&self) -> [u8; 12] {
        let counter = self.nonce_counter.fetch_add(1, Ordering::SeqCst);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&self.nonce_prefix);
        nonce[4..].copy_from_slice(&counter.to_le_bytes());
        nonce
    }

    /// Encrypt a packet (prepends nonce to output)
    pub fn encrypt_packet(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.next_nonce();
        let ciphertext = self.ctx.encrypt(&nonce, aad, plaintext)?;

        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);

        Ok(result)
    }

    /// Decrypt a packet (expects nonce prepended)
    pub fn decrypt_packet(&self, aad: &[u8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if data.len() < 12 {
            return Err(CryptoError::InvalidNonce);
        }

        let nonce = &data[..12];
        let ciphertext = &data[12..];

        self.ctx.decrypt(nonce, aad, ciphertext)
    }

    /// Encrypt multiple packets in parallel
    pub fn encrypt_batch(
        &self,
        aad: &[u8],
        packets: &[Vec<u8>],
    ) -> Vec<Result<Vec<u8>, CryptoError>> {
        use rayon::prelude::*;

        packets
            .par_iter()
            .map(|packet| self.encrypt_packet(aad, packet))
            .collect()
    }

    /// Decrypt multiple packets in parallel
    pub fn decrypt_batch(
        &self,
        aad: &[u8],
        packets: &[Vec<u8>],
    ) -> Vec<Result<Vec<u8>, CryptoError>> {
        use rayon::prelude::*;

        packets
            .par_iter()
            .map(|packet| self.decrypt_packet(aad, packet))
            .collect()
    }
}

/// Get crypto hardware info
pub fn crypto_info() -> CryptoInfo {
    CryptoInfo {
        has_aes_ni: CryptoAlgorithm::has_aes_ni(),
        recommended_algorithm: CryptoAlgorithm::auto_select(),
        estimated_throughput_mbps: CryptoAlgorithm::auto_select().estimated_throughput(),
    }
}

#[derive(Debug, Clone)]
pub struct CryptoInfo {
    pub has_aes_ni: bool,
    pub recommended_algorithm: CryptoAlgorithm,
    pub estimated_throughput_mbps: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_algorithm_selection() {
        let algo = CryptoAlgorithm::auto_select();
        println!("Selected algorithm: {:?}", algo);
        println!("Has AES-NI: {}", CryptoAlgorithm::has_aes_ni());
        assert!(algo.estimated_throughput() >= 500);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key = [0u8; 32];
        let ctx = CryptoContext::auto(&key).unwrap();

        let nonce = [1u8; 12];
        let aad = b"additional data";
        let plaintext = b"Hello, World!";

        let ciphertext = ctx.encrypt(&nonce, aad, plaintext).unwrap();
        let decrypted = ctx.decrypt(&nonce, aad, &ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_in_place() {
        let key = [0u8; 32];
        let ctx = CryptoContext::auto(&key).unwrap();

        let nonce = [2u8; 12];
        let aad = b"aad";
        let mut data = b"test data".to_vec();
        let original = data.clone();

        ctx.encrypt_in_place(&nonce, aad, &mut data).unwrap();
        assert_ne!(data[..original.len()], original[..]);

        ctx.decrypt_in_place(&nonce, aad, &mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_batch_crypto() {
        let key = [0u8; 32];
        let batch = BatchCrypto::new(CryptoAlgorithm::auto_select(), &key, [0, 0, 0, 0]).unwrap();

        let aad = b"batch aad";
        let packet = b"test packet data";

        let encrypted = batch.encrypt_packet(aad, packet).unwrap();
        let decrypted = batch.decrypt_packet(aad, &encrypted).unwrap();

        assert_eq!(decrypted, packet);
    }

    #[test]
    fn test_batch_parallel() {
        let key = [0u8; 32];
        let batch = BatchCrypto::new(CryptoAlgorithm::auto_select(), &key, [1, 2, 3, 4]).unwrap();

        let aad = b"parallel";
        let packets: Vec<Vec<u8>> = (0..100).map(|i| vec![i as u8; 100]).collect();

        let encrypted: Vec<_> = batch
            .encrypt_batch(aad, &packets)
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        let decrypted: Vec<_> = batch
            .decrypt_batch(aad, &encrypted)
            .into_iter()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(decrypted, packets);
    }

    #[test]
    fn test_crypto_info() {
        let info = crypto_info();
        println!("Crypto info: {:?}", info);
        assert!(info.estimated_throughput_mbps >= 500);
    }
}
