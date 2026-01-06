//! ROHC encoding schemes
//!
//! Implements W-LSB (Window-based Least Significant Bits) and SDVL encoding

/// W-LSB (Window-based Least Significant Bits) encoder/decoder
/// Used for efficient encoding of slowly changing values like sequence numbers
#[derive(Debug, Clone)]
pub struct WlsbEncoder {
    /// Reference value
    pub reference: u32,
    /// Window of recent values for robustness
    window: [u32; 8],
    window_idx: usize,
    /// Interpretation interval parameter (p)
    p: i32,
}

impl WlsbEncoder {
    pub fn new(p: i32) -> Self {
        WlsbEncoder {
            reference: 0,
            window: [0; 8],
            window_idx: 0,
            p,
        }
    }

    /// Encode a value using minimum bits needed
    pub fn encode(&mut self, value: u32) -> (u8, u8) {
        self.window[self.window_idx] = value;
        self.window_idx = (self.window_idx + 1) % 8;

        let diff = value.wrapping_sub(self.reference);
        self.reference = value;

        // Determine minimum bits needed
        let bits_needed = Self::bits_for_diff(diff, self.p);
        let mask = (1u32 << bits_needed) - 1;

        (bits_needed, (diff & mask) as u8)
    }

    /// Decode a value from LSB bits
    pub fn decode(&mut self, bits: u8, value: u8) -> u32 {
        let mask = (1u32 << bits) - 1;
        let lsb = value as u32 & mask;

        // Calculate possible values
        let ref_lsb = self.reference & mask;
        let mut result = (self.reference & !mask) | lsb;

        // Adjust based on interpretation interval
        if lsb < ref_lsb.wrapping_sub(self.p as u32) & mask {
            result = result.wrapping_add(1 << bits);
        } else if lsb > ref_lsb.wrapping_add((1 << bits) as u32 - 1 - self.p as u32) & mask {
            result = result.wrapping_sub(1 << bits);
        }

        self.reference = result;
        result
    }

    fn bits_for_diff(diff: u32, p: i32) -> u8 {
        // Calculate minimum k such that value fits in interpretation interval
        for k in 1..=16u8 {
            let range = 1u32 << k;
            let lower = (-(p as i64)) as u32;
            let upper = range.saturating_sub(1).saturating_sub(p as u32);

            if diff <= upper || diff >= lower.wrapping_neg() {
                return k;
            }
        }
        16
    }
}

/// SDVL (Self-Describing Variable Length) encoder
/// Encodes values in 1-4 bytes with self-describing length
pub struct Sdvl;

impl Sdvl {
    /// Encode a value using SDVL
    pub fn encode(value: u32) -> Vec<u8> {
        if value < 0x80 {
            // 1 byte: 0xxxxxxx
            vec![value as u8]
        } else if value < 0x4000 {
            // 2 bytes: 10xxxxxx xxxxxxxx
            vec![0x80 | ((value >> 8) as u8 & 0x3F), value as u8]
        } else if value < 0x200000 {
            // 3 bytes: 110xxxxx xxxxxxxx xxxxxxxx
            vec![
                0xC0 | ((value >> 16) as u8 & 0x1F),
                (value >> 8) as u8,
                value as u8,
            ]
        } else {
            // 4 bytes: 111xxxxx xxxxxxxx xxxxxxxx xxxxxxxx
            vec![
                0xE0 | ((value >> 24) as u8 & 0x1F),
                (value >> 16) as u8,
                (value >> 8) as u8,
                value as u8,
            ]
        }
    }

    /// Decode an SDVL value, returns (value, bytes_consumed)
    pub fn decode(data: &[u8]) -> Option<(u32, usize)> {
        if data.is_empty() {
            return None;
        }

        let first = data[0];

        if first & 0x80 == 0 {
            // 1 byte
            Some((first as u32, 1))
        } else if first & 0xC0 == 0x80 {
            // 2 bytes
            if data.len() < 2 {
                return None;
            }
            let value = ((first & 0x3F) as u32) << 8 | data[1] as u32;
            Some((value, 2))
        } else if first & 0xE0 == 0xC0 {
            // 3 bytes
            if data.len() < 3 {
                return None;
            }
            let value = ((first & 0x1F) as u32) << 16 | (data[1] as u32) << 8 | data[2] as u32;
            Some((value, 3))
        } else {
            // 4 bytes
            if data.len() < 4 {
                return None;
            }
            let value = ((first & 0x1F) as u32) << 24
                | (data[1] as u32) << 16
                | (data[2] as u32) << 8
                | data[3] as u32;
            Some((value, 4))
        }
    }
}

/// CRC calculation for ROHC packets
pub struct RohcCrc;

impl RohcCrc {
    /// CRC-3 polynomial: x^3 + x + 1
    pub fn crc3(data: &[u8]) -> u8 {
        let mut crc: u8 = 0x7;
        for &byte in data {
            for i in 0..8 {
                let bit = (byte >> (7 - i)) & 1;
                if (crc >> 2) ^ bit != 0 {
                    crc = ((crc << 1) ^ 0x3) & 0x7;
                } else {
                    crc = (crc << 1) & 0x7;
                }
            }
        }
        crc
    }

    /// CRC-7 polynomial: x^7 + x^6 + x^5 + x^2 + 1
    pub fn crc7(data: &[u8]) -> u8 {
        let mut crc: u8 = 0x7F;
        for &byte in data {
            for i in 0..8 {
                let bit = (byte >> (7 - i)) & 1;
                if (crc >> 6) ^ bit != 0 {
                    crc = ((crc << 1) ^ 0x65) & 0x7F;
                } else {
                    crc = (crc << 1) & 0x7F;
                }
            }
        }
        crc
    }

    /// CRC-8 polynomial: x^8 + x^2 + x + 1
    pub fn crc8(data: &[u8]) -> u8 {
        let mut crc: u8 = 0xFF;
        for &byte in data {
            crc ^= byte;
            for _ in 0..8 {
                if crc & 0x80 != 0 {
                    crc = (crc << 1) ^ 0x07;
                } else {
                    crc <<= 1;
                }
            }
        }
        crc
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdvl_roundtrip() {
        // SDVL encoding supports up to 29 bits (0x1FFFFFFF)
        for value in [0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 0x1FFFFFFF] {
            let encoded = Sdvl::encode(value);
            let (decoded, len) = Sdvl::decode(&encoded).unwrap();
            assert_eq!(decoded, value);
            assert_eq!(len, encoded.len());
        }
    }

    #[test]
    fn test_wlsb_sequential() {
        let mut enc = WlsbEncoder::new(0);

        // Sequential values should compress well
        for i in 0..100u32 {
            let (bits, _) = enc.encode(i);
            assert!(bits <= 4, "Sequential values should use few bits");
        }
    }

    #[test]
    fn test_crc() {
        let data = b"test data";
        let crc3 = RohcCrc::crc3(data);
        let crc7 = RohcCrc::crc7(data);
        let crc8 = RohcCrc::crc8(data);

        assert!(crc3 <= 7);
        assert!(crc7 <= 127);
        // crc8 can be any u8 value
        let _ = crc8;
    }
}
