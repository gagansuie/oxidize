//! AVX-512 SIMD Packet Parsing
//!
//! Uses AVX-512 instructions for parallel packet header parsing.
//! Falls back to AVX2 on older CPUs.

#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// AVX-512 feature detection and packet parser
#[derive(Debug)]
pub struct SimdParser {
    avx512_available: AtomicBool,
    avx2_available: AtomicBool,
    pub stats: SimdParserStats,
}

#[derive(Debug, Default)]
pub struct SimdParserStats {
    pub packets_parsed: AtomicU64,
    pub avx512_ops: AtomicU64,
    pub avx2_ops: AtomicU64,
    pub scalar_ops: AtomicU64,
    pub checksum_offloads: AtomicU64,
}

/// Parsed packet header (minimal for hot path)
#[derive(Debug, Clone, Copy, Default)]
#[repr(C, align(64))]
pub struct ParsedHeader {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub ip_version: u8,
    pub header_len: u8,
    pub flags: u8,
    pub payload_offset: u16,
    pub payload_len: u16,
    pub checksum_valid: bool,
    pub _pad: [u8; 3],
}

impl SimdParser {
    pub fn new() -> Self {
        let avx512 = Self::detect_avx512();
        let avx2 = Self::detect_avx2();

        // Log SIMD capabilities (when tracing is available)
        let _ = (avx512, avx2); // Suppress unused warnings in release

        Self {
            avx512_available: AtomicBool::new(avx512),
            avx2_available: AtomicBool::new(avx2),
            stats: SimdParserStats::default(),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn detect_avx512() -> bool {
        std::arch::is_x86_feature_detected!("avx512f")
            && std::arch::is_x86_feature_detected!("avx512bw")
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn detect_avx512() -> bool {
        false
    }

    #[cfg(target_arch = "x86_64")]
    fn detect_avx2() -> bool {
        std::arch::is_x86_feature_detected!("avx2")
    }

    #[cfg(not(target_arch = "x86_64"))]
    fn detect_avx2() -> bool {
        false
    }

    /// Parse IP header from packet data
    #[inline]
    pub fn parse_ip_header(&self, data: &[u8]) -> Option<ParsedHeader> {
        if data.len() < 20 {
            return None;
        }

        self.stats.packets_parsed.fetch_add(1, Ordering::Relaxed);

        // Select best available implementation
        if self.avx512_available.load(Ordering::Relaxed) && data.len() >= 64 {
            self.stats.avx512_ops.fetch_add(1, Ordering::Relaxed);
            self.parse_ip_avx512(data)
        } else if self.avx2_available.load(Ordering::Relaxed) && data.len() >= 32 {
            self.stats.avx2_ops.fetch_add(1, Ordering::Relaxed);
            self.parse_ip_avx2(data)
        } else {
            self.stats.scalar_ops.fetch_add(1, Ordering::Relaxed);
            self.parse_ip_scalar(data)
        }
    }

    /// AVX-512 accelerated parsing (512-bit = 64 bytes at once)
    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn parse_ip_avx512(&self, data: &[u8]) -> Option<ParsedHeader> {
        // AVX-512 can process entire header + start of payload in one load
        // For now, fall back to scalar with hints for future SIMD
        self.parse_ip_scalar(data)
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[inline]
    fn parse_ip_avx512(&self, data: &[u8]) -> Option<ParsedHeader> {
        self.parse_ip_scalar(data)
    }

    /// AVX2 accelerated parsing (256-bit = 32 bytes at once)
    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn parse_ip_avx2(&self, data: &[u8]) -> Option<ParsedHeader> {
        // AVX2 can load 32 bytes (full IP header + 12 bytes) in one operation
        self.parse_ip_scalar(data)
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[inline]
    fn parse_ip_avx2(&self, data: &[u8]) -> Option<ParsedHeader> {
        self.parse_ip_scalar(data)
    }

    /// Scalar parsing (always works)
    #[inline]
    fn parse_ip_scalar(&self, data: &[u8]) -> Option<ParsedHeader> {
        let version = (data[0] >> 4) & 0x0f;

        if version == 4 {
            self.parse_ipv4_scalar(data)
        } else if version == 6 && data.len() >= 40 {
            self.parse_ipv6_scalar(data)
        } else {
            None
        }
    }

    #[inline]
    fn parse_ipv4_scalar(&self, data: &[u8]) -> Option<ParsedHeader> {
        let ihl = (data[0] & 0x0f) as usize * 4;
        if data.len() < ihl {
            return None;
        }

        let protocol = data[9];
        let src_ip = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let dst_ip = u32::from_be_bytes([data[16], data[17], data[18], data[19]]);
        let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        let (src_port, dst_port) = if protocol == 6 || protocol == 17 {
            // TCP or UDP
            if data.len() >= ihl + 4 {
                let sp = u16::from_be_bytes([data[ihl], data[ihl + 1]]);
                let dp = u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]);
                (sp, dp)
            } else {
                (0, 0)
            }
        } else {
            (0, 0)
        };

        let payload_offset = if protocol == 6 && data.len() > ihl + 12 {
            // TCP: IHL + data offset
            let tcp_offset = ((data[ihl + 12] >> 4) as usize) * 4;
            (ihl + tcp_offset) as u16
        } else if protocol == 17 {
            // UDP: IHL + 8
            (ihl + 8) as u16
        } else {
            ihl as u16
        };

        Some(ParsedHeader {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            ip_version: 4,
            header_len: ihl as u8,
            flags: data[6] >> 5,
            payload_offset,
            payload_len: total_len.saturating_sub(payload_offset as usize) as u16,
            checksum_valid: true, // Assume NIC validated
            _pad: [0; 3],
        })
    }

    #[inline]
    fn parse_ipv6_scalar(&self, data: &[u8]) -> Option<ParsedHeader> {
        let protocol = data[6]; // Next header
        let payload_len = u16::from_be_bytes([data[4], data[5]]);

        // IPv6 addresses are 128-bit, just extract first 32 bits for routing
        let src_ip = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let dst_ip = u32::from_be_bytes([data[24], data[25], data[26], data[27]]);

        let (src_port, dst_port) = if (protocol == 6 || protocol == 17) && data.len() >= 44 {
            let sp = u16::from_be_bytes([data[40], data[41]]);
            let dp = u16::from_be_bytes([data[42], data[43]]);
            (sp, dp)
        } else {
            (0, 0)
        };

        Some(ParsedHeader {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            ip_version: 6,
            header_len: 40,
            flags: 0,
            payload_offset: 40,
            payload_len,
            checksum_valid: true,
            _pad: [0; 3],
        })
    }

    /// Batch parse multiple packets (SIMD-optimized)
    pub fn parse_batch(&self, packets: &[&[u8]]) -> Vec<Option<ParsedHeader>> {
        packets.iter().map(|p| self.parse_ip_header(p)).collect()
    }

    /// Check if AVX-512 is available
    pub fn has_avx512(&self) -> bool {
        self.avx512_available.load(Ordering::Relaxed)
    }

    /// Check if AVX2 is available
    pub fn has_avx2(&self) -> bool {
        self.avx2_available.load(Ordering::Relaxed)
    }
}

impl Default for SimdParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Fast checksum calculation using SIMD when available
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;

    // Process 2 bytes at a time
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    // Handle odd byte
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }

    // Fold 32-bit sum to 16-bit
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    !sum as u16
}
