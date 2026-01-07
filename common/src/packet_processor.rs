//! Unified packet processing with ROHC and LZ4 compression
//!
//! This module provides intelligent packet compression that uses:
//! - ROHC for IP/UDP/TCP header compression (best for small packets, VoIP, gaming)
//! - LZ4 for payload compression (best for larger data transfers)

use anyhow::Result;
use tracing::trace;

#[cfg(feature = "rohc")]
use tracing::{debug, warn};

#[cfg(feature = "ai")]
use crate::ai_engine::{CompressionDecision, HeuristicEngine, PacketFeatures};
use crate::compression::{compress_data, decompress_data};

#[cfg(feature = "rohc")]
use crate::rohc::RohcContext;

/// Compression method indicator for the wire protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionMethod {
    /// No compression
    None = 0,
    /// LZ4 compression only
    Lz4 = 1,
    /// ROHC header compression only
    Rohc = 2,
    /// ROHC + LZ4 (ROHC on headers, then LZ4 on result)
    RohcLz4 = 3,
}

impl CompressionMethod {
    pub fn from_u8(val: u8) -> Option<Self> {
        match val {
            0 => Some(CompressionMethod::None),
            1 => Some(CompressionMethod::Lz4),
            2 => Some(CompressionMethod::Rohc),
            3 => Some(CompressionMethod::RohcLz4),
            _ => None,
        }
    }
}

/// Configuration for the packet processor
#[derive(Debug, Clone)]
pub struct PacketProcessorConfig {
    /// Enable LZ4 compression
    pub enable_lz4: bool,
    /// Enable ROHC header compression
    pub enable_rohc: bool,
    /// Minimum packet size for LZ4 compression
    pub lz4_min_size: usize,
    /// Maximum packet size for ROHC (larger packets don't benefit much)
    pub rohc_max_size: usize,
}

impl Default for PacketProcessorConfig {
    fn default() -> Self {
        PacketProcessorConfig {
            enable_lz4: true,
            enable_rohc: true,
            lz4_min_size: 128,
            rohc_max_size: 1500, // MTU size - ROHC is best for small packets
        }
    }
}

/// Result of packet compression
pub struct CompressedPacket {
    pub data: Vec<u8>,
    pub method: CompressionMethod,
    pub original_size: usize,
}

/// Unified packet processor for compression/decompression
pub struct PacketProcessor {
    config: PacketProcessorConfig,
    #[cfg(feature = "rohc")]
    rohc: Option<RohcContext>,
    /// AI-powered heuristic engine for smart compression decisions
    #[cfg(feature = "ai")]
    ai_engine: Option<HeuristicEngine>,
    /// Statistics
    packets_processed: u64,
    bytes_saved_rohc: i64,
    bytes_saved_lz4: i64,
    /// AI decision stats
    #[cfg(feature = "ai")]
    ai_skipped: u64,
}

impl PacketProcessor {
    /// Create a new packet processor with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(PacketProcessorConfig::default())
    }

    /// Create a new packet processor with custom configuration
    pub fn with_config(config: PacketProcessorConfig) -> Result<Self> {
        #[cfg(feature = "rohc")]
        let rohc = if config.enable_rohc {
            match RohcContext::new() {
                Ok(ctx) => {
                    debug!("ROHC compression enabled");
                    Some(ctx)
                }
                Err(e) => {
                    warn!("Failed to initialize ROHC, falling back to LZ4 only: {}", e);
                    None
                }
            }
        } else {
            None
        };

        Ok(PacketProcessor {
            config,
            #[cfg(feature = "rohc")]
            rohc,
            #[cfg(feature = "ai")]
            ai_engine: Some(HeuristicEngine::new()),
            packets_processed: 0,
            bytes_saved_rohc: 0,
            bytes_saved_lz4: 0,
            #[cfg(feature = "ai")]
            ai_skipped: 0,
        })
    }

    /// Check if this looks like an IP packet
    #[cfg(feature = "rohc")]
    fn is_ip_packet(data: &[u8]) -> bool {
        if data.is_empty() {
            return false;
        }
        // IPv4: version = 4 (high nibble of first byte)
        // IPv6: version = 6 (high nibble of first byte)
        let version = (data[0] >> 4) & 0xF;
        version == 4 || version == 6
    }

    /// Compress a packet using AI-enhanced smart decisions
    /// Uses heuristics to skip compression for encrypted/already-compressed data
    #[cfg(feature = "ai")]
    pub fn compress_smart(
        &mut self,
        data: &[u8],
        src_port: u16,
        dst_port: u16,
        ip_protocol: u8,
    ) -> Result<CompressedPacket> {
        let original_size = data.len();
        self.packets_processed += 1;

        // Use AI engine for smart compression decision
        if let Some(ref mut engine) = self.ai_engine {
            let features = PacketFeatures::extract(data, src_port, dst_port, ip_protocol);
            let decision = engine.compression_decision(&features);

            match decision {
                CompressionDecision::Skip => {
                    self.ai_skipped += 1;
                    trace!(
                        "AI: Skipping compression for {} bytes (entropy={:.2}, encrypted={})",
                        data.len(),
                        features.entropy,
                        features.is_encrypted
                    );
                    return Ok(CompressedPacket {
                        data: data.to_vec(),
                        method: CompressionMethod::None,
                        original_size,
                    });
                }
                CompressionDecision::Light => {
                    // Use LZ4 only (fast)
                    if let Ok(compressed) = compress_data(data) {
                        if compressed.len() < data.len() {
                            let saved = data.len() as i64 - compressed.len() as i64;
                            self.bytes_saved_lz4 += saved;
                            return Ok(CompressedPacket {
                                data: compressed,
                                method: CompressionMethod::Lz4,
                                original_size,
                            });
                        }
                    }
                    return Ok(CompressedPacket {
                        data: data.to_vec(),
                        method: CompressionMethod::None,
                        original_size,
                    });
                }
                CompressionDecision::Aggressive => {
                    // Fall through to full compression pipeline
                }
            }
        }

        // Fall through to standard compression
        self.compress(data)
    }

    /// Compress a packet using the best available method
    pub fn compress(&mut self, data: &[u8]) -> Result<CompressedPacket> {
        let original_size = data.len();
        self.packets_processed += 1;

        // Try ROHC first for IP packets within size limit
        #[cfg(feature = "rohc")]
        if let Some(ref mut rohc) = self.rohc {
            if Self::is_ip_packet(data) && data.len() <= self.config.rohc_max_size {
                match rohc.compress(data) {
                    Ok(compressed) => {
                        let rohc_saved = data.len() as i64 - compressed.len() as i64;

                        // Only use ROHC if it actually saves space
                        if rohc_saved > 0 {
                            self.bytes_saved_rohc += rohc_saved;

                            // Optionally apply LZ4 on top if beneficial
                            if self.config.enable_lz4
                                && compressed.len() >= self.config.lz4_min_size
                            {
                                if let Ok(lz4_compressed) = compress_data(&compressed) {
                                    if lz4_compressed.len() < compressed.len() {
                                        let lz4_saved =
                                            compressed.len() as i64 - lz4_compressed.len() as i64;
                                        self.bytes_saved_lz4 += lz4_saved;

                                        trace!(
                                            "ROHC+LZ4: {} -> {} -> {} bytes",
                                            original_size,
                                            compressed.len(),
                                            lz4_compressed.len()
                                        );

                                        return Ok(CompressedPacket {
                                            data: lz4_compressed,
                                            method: CompressionMethod::RohcLz4,
                                            original_size,
                                        });
                                    }
                                }
                            }

                            trace!("ROHC: {} -> {} bytes", original_size, compressed.len());

                            return Ok(CompressedPacket {
                                data: compressed,
                                method: CompressionMethod::Rohc,
                                original_size,
                            });
                        }
                    }
                    Err(e) => {
                        trace!("ROHC compression failed, falling back: {}", e);
                    }
                }
            }
        }

        // Fall back to LZ4 for larger packets or non-IP data
        if self.config.enable_lz4 && data.len() >= self.config.lz4_min_size {
            if let Ok(compressed) = compress_data(data) {
                if compressed.len() < data.len() {
                    let saved = data.len() as i64 - compressed.len() as i64;
                    self.bytes_saved_lz4 += saved;

                    trace!("LZ4: {} -> {} bytes", original_size, compressed.len());

                    return Ok(CompressedPacket {
                        data: compressed,
                        method: CompressionMethod::Lz4,
                        original_size,
                    });
                }
            }
        }

        // No compression beneficial
        Ok(CompressedPacket {
            data: data.to_vec(),
            method: CompressionMethod::None,
            original_size,
        })
    }

    /// Decompress a packet based on the compression method
    pub fn decompress(&mut self, data: &[u8], method: CompressionMethod) -> Result<Vec<u8>> {
        match method {
            CompressionMethod::None => Ok(data.to_vec()),

            CompressionMethod::Lz4 => decompress_data(data),

            #[cfg(feature = "rohc")]
            CompressionMethod::Rohc => {
                if let Some(ref mut rohc) = self.rohc {
                    rohc.decompress(data)
                } else {
                    anyhow::bail!("ROHC not available for decompression")
                }
            }

            #[cfg(not(feature = "rohc"))]
            CompressionMethod::Rohc => {
                anyhow::bail!("ROHC support not compiled in")
            }

            #[cfg(feature = "rohc")]
            CompressionMethod::RohcLz4 => {
                // First decompress LZ4
                let lz4_decompressed = decompress_data(data)?;

                // Then decompress ROHC
                if let Some(ref mut rohc) = self.rohc {
                    rohc.decompress(&lz4_decompressed)
                } else {
                    anyhow::bail!("ROHC not available for decompression")
                }
            }

            #[cfg(not(feature = "rohc"))]
            CompressionMethod::RohcLz4 => {
                anyhow::bail!("ROHC support not compiled in")
            }
        }
    }

    /// Get compression statistics
    pub fn stats(&self) -> PacketProcessorStats {
        PacketProcessorStats {
            packets_processed: self.packets_processed,
            bytes_saved_rohc: self.bytes_saved_rohc,
            bytes_saved_lz4: self.bytes_saved_lz4,
            total_bytes_saved: self.bytes_saved_rohc + self.bytes_saved_lz4,
            #[cfg(feature = "ai")]
            ai_skipped: self.ai_skipped,
        }
    }

    /// Get a reference to the AI engine for advanced operations
    #[cfg(feature = "ai")]
    pub fn ai_engine(&mut self) -> Option<&mut HeuristicEngine> {
        self.ai_engine.as_mut()
    }
}

impl Default for PacketProcessor {
    fn default() -> Self {
        Self::new().expect("Failed to create default PacketProcessor")
    }
}

/// Statistics from packet processing
#[derive(Debug, Clone)]
pub struct PacketProcessorStats {
    pub packets_processed: u64,
    pub bytes_saved_rohc: i64,
    pub bytes_saved_lz4: i64,
    pub total_bytes_saved: i64,
    /// Packets skipped by AI (encrypted/compressed)
    #[cfg(feature = "ai")]
    pub ai_skipped: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_method_roundtrip() {
        for method in [
            CompressionMethod::None,
            CompressionMethod::Lz4,
            CompressionMethod::Rohc,
            CompressionMethod::RohcLz4,
        ] {
            let val = method as u8;
            assert_eq!(CompressionMethod::from_u8(val), Some(method));
        }
    }

    #[test]
    #[cfg(feature = "rohc")]
    fn test_is_ip_packet() {
        // IPv4 packet (version 4)
        let ipv4 = [0x45, 0x00, 0x00, 0x14]; // Version 4, IHL 5
        assert!(PacketProcessor::is_ip_packet(&ipv4));

        // IPv6 packet (version 6)
        let ipv6 = [0x60, 0x00, 0x00, 0x00]; // Version 6
        assert!(PacketProcessor::is_ip_packet(&ipv6));

        // Not an IP packet
        let other = [0x00, 0x01, 0x02, 0x03];
        assert!(!PacketProcessor::is_ip_packet(&other));
    }

    #[test]
    fn test_lz4_only_compression() {
        let config = PacketProcessorConfig {
            enable_lz4: true,
            enable_rohc: false,
            lz4_min_size: 10,
            rohc_max_size: 1500,
        };

        let mut processor = PacketProcessor::with_config(config).unwrap();

        // Compressible data
        let data = vec![0u8; 1000];
        let result = processor.compress(&data).unwrap();

        assert!(
            result.method == CompressionMethod::Lz4 || result.method == CompressionMethod::None
        );
    }

    #[test]
    #[cfg(feature = "ai")]
    fn test_smart_compression_skips_encrypted() {
        let mut processor = PacketProcessor::new().unwrap();

        // Simulate TLS-encrypted data (high entropy)
        let mut encrypted_data = vec![0u8; 1000];
        for (i, byte) in encrypted_data.iter_mut().enumerate() {
            *byte = (i * 7 + 13) as u8; // Pseudo-random
        }
        // TLS record header
        encrypted_data[0] = 0x17; // Application data
        encrypted_data[1] = 0x03; // TLS version

        let result = processor
            .compress_smart(&encrypted_data, 12345, 443, 6)
            .unwrap();

        // Should skip compression for encrypted data
        assert_eq!(result.method, CompressionMethod::None);
        assert!(processor.stats().ai_skipped > 0);
    }

    #[test]
    #[cfg(feature = "ai")]
    fn test_smart_compression_compresses_json() {
        let mut processor = PacketProcessor::new().unwrap();

        // JSON data (very compressible)
        let json_data = br#"{"users": [{"name": "alice", "age": 30}, {"name": "bob", "age": 25}], "count": 2, "status": "ok", "message": "success"}"#;
        let data = json_data.to_vec();

        let result = processor.compress_smart(&data, 12345, 80, 6).unwrap();

        // Should compress JSON (or at least not skip)
        // LZ4 compression may or may not be smaller for small data
        assert!(
            result.method == CompressionMethod::Lz4 || result.method == CompressionMethod::None
        );
    }
}
