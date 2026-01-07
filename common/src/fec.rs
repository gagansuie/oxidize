use anyhow::Result;
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Forward Error Correction encoder/decoder
/// Adds redundancy to prevent retransmissions on lossy networks
pub struct FecEncoder {
    data_shards: usize,
    parity_shards: usize,
    rs: ReedSolomon,
}

impl FecEncoder {
    /// Create new FEC encoder
    /// data_shards: Number of original data packets
    /// parity_shards: Number of redundant packets to add
    /// Can recover from losing up to parity_shards packets
    pub fn new(data_shards: usize, parity_shards: usize) -> Result<Self> {
        let rs = ReedSolomon::new(data_shards, parity_shards)?;
        Ok(Self {
            data_shards,
            parity_shards,
            rs,
        })
    }

    /// Encode data with FEC
    /// Returns original shards + parity shards
    pub fn encode(&self, data: &[u8]) -> Result<Vec<Vec<u8>>> {
        let shard_size = data.len().div_ceil(self.data_shards);
        let mut shards: Vec<Vec<u8>> = Vec::with_capacity(self.data_shards + self.parity_shards);

        // Split data into shards
        for i in 0..self.data_shards {
            let start = i * shard_size;
            let end = ((i + 1) * shard_size).min(data.len());
            let mut shard = vec![0u8; shard_size];
            if start < data.len() {
                shard[..end - start].copy_from_slice(&data[start..end]);
            }
            shards.push(shard);
        }

        // Add empty parity shards
        for _ in 0..self.parity_shards {
            shards.push(vec![0u8; shard_size]);
        }

        // Encode
        self.rs.encode(&mut shards)?;

        Ok(shards)
    }

    /// Decode data from shards (some may be missing/corrupted)
    /// missing_indices: Indices of shards that are corrupted/missing
    pub fn decode(&self, shards: &mut [Vec<u8>], missing_indices: &[usize]) -> Result<Vec<u8>> {
        // Convert to Option tuple format required by reed-solomon
        let mut option_shards: Vec<Option<Vec<u8>>> = shards
            .iter()
            .enumerate()
            .map(|(i, s)| {
                if missing_indices.contains(&i) {
                    None
                } else {
                    Some(s.clone())
                }
            })
            .collect();

        // Reconstruct
        self.rs.reconstruct(&mut option_shards)?;

        // Combine data shards
        let mut result = Vec::new();
        for shard in option_shards.iter().take(self.data_shards).flatten() {
            result.extend_from_slice(shard);
        }

        Ok(result)
    }

    /// Calculate overhead percentage
    pub fn overhead_percent(&self) -> f64 {
        (self.parity_shards as f64 / self.data_shards as f64) * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fec_encode_decode() {
        let encoder = FecEncoder::new(10, 3).unwrap();
        let data = b"Hello, this is test data for FEC encoding!";

        let shards = encoder.encode(data).unwrap();
        assert_eq!(shards.len(), 13); // 10 data + 3 parity

        // Simulate losing 2 shards
        let mut shards_copy = shards.clone();
        shards_copy[2] = vec![0u8; shards_copy[2].len()];
        shards_copy[7] = vec![0u8; shards_copy[7].len()];

        let decoded = encoder.decode(&mut shards_copy, &[2, 7]).unwrap();
        assert_eq!(&decoded[..data.len()], data);
    }

    #[test]
    fn test_fec_overhead() {
        let encoder = FecEncoder::new(10, 2).unwrap();
        assert_eq!(encoder.overhead_percent(), 20.0);
    }
}
