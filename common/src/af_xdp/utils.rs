//! Kernel Bypass Utilities - Consolidated from kernel_bypass.rs
//!
//! High-performance data structures for packet processing:
//! - Cache-line aligned counters
//! - Lock-free SPSC ring buffers
//! - Zero-copy packet buffers
//! - Packet parsing and validation
//! - Security utilities

#![allow(dead_code)]

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Cache line size (64 bytes on most modern CPUs)
pub const CACHE_LINE_SIZE: usize = 64;

/// Maximum burst size for batch processing
pub const MAX_BURST_SIZE: usize = 64;

/// Default packet buffer size (supports jumbo frames)
pub const PACKET_BUFFER_SIZE: usize = 9728;

// =============================================================================
// Cache-Line Aligned Counter
// =============================================================================

/// Cache-line aligned counter to prevent false sharing
#[repr(C, align(64))]
pub struct AlignedCounter {
    pub value: AtomicU64,
    _padding: [u8; 56],
}

impl AlignedCounter {
    pub const fn new(value: u64) -> Self {
        Self {
            value: AtomicU64::new(value),
            _padding: [0; 56],
        }
    }

    #[inline(always)]
    pub fn inc(&self) {
        self.value.fetch_add(1, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn add(&self, n: u64) {
        self.value.fetch_add(n, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }
}

impl Default for AlignedCounter {
    fn default() -> Self {
        Self::new(0)
    }
}

// =============================================================================
// Lock-Free SPSC Ring Buffer
// =============================================================================

/// Lock-free SPSC (Single Producer Single Consumer) ring buffer
#[repr(C)]
pub struct SpscRing<T> {
    prod_head: AtomicUsize,
    _prod_pad: [u8; CACHE_LINE_SIZE - 8],
    cons_head: AtomicUsize,
    _cons_pad: [u8; CACHE_LINE_SIZE - 8],
    capacity: usize,
    mask: usize,
    buffer: Box<[UnsafeCell<MaybeUninit<T>>]>,
}

unsafe impl<T: Send> Send for SpscRing<T> {}
unsafe impl<T: Send> Sync for SpscRing<T> {}

impl<T> SpscRing<T> {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.next_power_of_two();
        let mask = capacity - 1;
        let buffer: Vec<UnsafeCell<MaybeUninit<T>>> = (0..capacity)
            .map(|_| UnsafeCell::new(MaybeUninit::uninit()))
            .collect();

        Self {
            prod_head: AtomicUsize::new(0),
            _prod_pad: [0; CACHE_LINE_SIZE - 8],
            cons_head: AtomicUsize::new(0),
            _cons_pad: [0; CACHE_LINE_SIZE - 8],
            capacity,
            mask,
            buffer: buffer.into_boxed_slice(),
        }
    }

    #[inline(always)]
    pub fn push(&self, value: T) -> bool {
        let prod = self.prod_head.load(Ordering::Relaxed);
        let cons = self.cons_head.load(Ordering::Acquire);

        if prod.wrapping_sub(cons) >= self.capacity {
            return false;
        }

        let idx = prod & self.mask;
        unsafe {
            (*self.buffer[idx].get()).write(value);
        }
        self.prod_head
            .store(prod.wrapping_add(1), Ordering::Release);
        true
    }

    #[inline(always)]
    pub fn pop(&self) -> Option<T> {
        let cons = self.cons_head.load(Ordering::Relaxed);
        let prod = self.prod_head.load(Ordering::Acquire);

        if cons == prod {
            return None;
        }

        let idx = cons & self.mask;
        let value = unsafe { (*self.buffer[idx].get()).assume_init_read() };
        self.cons_head
            .store(cons.wrapping_add(1), Ordering::Release);
        Some(value)
    }

    #[inline]
    pub fn push_batch(&self, values: &mut Vec<T>) -> usize {
        let prod = self.prod_head.load(Ordering::Relaxed);
        let cons = self.cons_head.load(Ordering::Acquire);

        let free = self.capacity - prod.wrapping_sub(cons);
        let count = std::cmp::min(free, values.len());

        if count == 0 {
            return 0;
        }

        for i in 0..count {
            let idx = (prod + i) & self.mask;
            unsafe {
                (*self.buffer[idx].get()).write(values.pop().unwrap());
            }
        }

        self.prod_head
            .store(prod.wrapping_add(count), Ordering::Release);
        count
    }

    #[inline]
    pub fn pop_batch(&self, output: &mut Vec<T>, max: usize) -> usize {
        let cons = self.cons_head.load(Ordering::Relaxed);
        let prod = self.prod_head.load(Ordering::Acquire);

        let available = prod.wrapping_sub(cons);
        let count = std::cmp::min(available, max);

        if count == 0 {
            return 0;
        }

        for i in 0..count {
            let idx = (cons + i) & self.mask;
            let value = unsafe { (*self.buffer[idx].get()).assume_init_read() };
            output.push(value);
        }

        self.cons_head
            .store(cons.wrapping_add(count), Ordering::Release);
        count
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        let prod = self.prod_head.load(Ordering::Relaxed);
        let cons = self.cons_head.load(Ordering::Relaxed);
        prod.wrapping_sub(cons)
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.capacity
    }
}

// =============================================================================
// Zero-Copy Packet Buffer
// =============================================================================

/// Zero-copy packet buffer with pre-allocated memory
#[repr(C, align(64))]
pub struct PacketBuffer {
    data: [u8; PACKET_BUFFER_SIZE],
    len: u32,
    offset: u16,
    queue_id: u16,
    timestamp_ns: u64,
    flags: u32,
    refcount: AtomicU32,
    pool_id: u32,
    rss_hash: u32,
}

impl PacketBuffer {
    #[inline]
    pub fn new() -> Self {
        Self {
            data: [0; PACKET_BUFFER_SIZE],
            len: 0,
            offset: 128,
            queue_id: 0,
            timestamp_ns: 0,
            flags: 0,
            refcount: AtomicU32::new(1),
            pool_id: 0,
            rss_hash: 0,
        }
    }

    #[inline(always)]
    pub fn data(&self) -> &[u8] {
        let start = self.offset as usize;
        let end = start + self.len as usize;
        &self.data[start..end]
    }

    #[inline(always)]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let start = self.offset as usize;
        let end = start + self.len as usize;
        &mut self.data[start..end]
    }

    #[inline]
    pub fn set_data(&mut self, data: &[u8]) {
        let start = self.offset as usize;
        let len = std::cmp::min(data.len(), PACKET_BUFFER_SIZE - start);
        self.data[start..start + len].copy_from_slice(&data[..len]);
        self.len = len as u32;
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn reset(&mut self) {
        self.len = 0;
        self.offset = 128;
        self.flags = 0;
        self.refcount.store(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_ref(&self) {
        self.refcount.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn dec_ref(&self) -> bool {
        self.refcount.fetch_sub(1, Ordering::Release) == 1
    }
}

impl Default for PacketBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Packet Flags
// =============================================================================

pub mod packet_flags {
    pub const PARSED: u32 = 1 << 0;
    pub const IPV4: u32 = 1 << 1;
    pub const IPV6: u32 = 1 << 2;
    pub const UDP: u32 = 1 << 3;
    pub const TCP: u32 = 1 << 4;
    pub const QUIC: u32 = 1 << 5;
    pub const CHECKSUM_VALID: u32 = 1 << 6;
    pub const CHECKSUM_BAD: u32 = 1 << 7;
    pub const VLAN: u32 = 1 << 8;
    pub const ENCRYPTED: u32 = 1 << 9;
    pub const COMPRESSED: u32 = 1 << 10;
    pub const FEC_PROTECTED: u32 = 1 << 11;
}

// =============================================================================
// Fast Packet Parser
// =============================================================================

/// Parsed packet information
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub src_addr: Option<SocketAddr>,
    pub dst_addr: Option<SocketAddr>,
    pub protocol: u8,
    pub payload_offset: usize,
    pub is_udp: bool,
    pub is_tunnel: bool,
}

/// Fast packet parser with prefetch hints
pub struct PacketParser;

impl PacketParser {
    /// Parse packet headers
    #[inline]
    pub fn parse_fast(data: &[u8]) -> Option<ParsedPacket> {
        if data.len() < 42 {
            return None;
        }

        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 {
            return None;
        }

        let ip_header = &data[14..];
        let version_ihl = ip_header[0];
        let version = version_ihl >> 4;
        let ihl = (version_ihl & 0x0F) as usize * 4;

        if version != 4 || ihl < 20 {
            return None;
        }

        let protocol = ip_header[9];
        let src_ip = Ipv4Addr::new(ip_header[12], ip_header[13], ip_header[14], ip_header[15]);
        let dst_ip = Ipv4Addr::new(ip_header[16], ip_header[17], ip_header[18], ip_header[19]);

        if protocol != 17 {
            return Some(ParsedPacket {
                src_addr: None,
                dst_addr: None,
                protocol,
                payload_offset: 14 + ihl,
                is_udp: false,
                is_tunnel: false,
            });
        }

        let udp_offset = 14 + ihl;
        if data.len() < udp_offset + 8 {
            return None;
        }

        let udp_header = &data[udp_offset..];
        let src_port = u16::from_be_bytes([udp_header[0], udp_header[1]]);
        let dst_port = u16::from_be_bytes([udp_header[2], udp_header[3]]);
        let is_tunnel = dst_port == 443 || dst_port == 51820 || dst_port == 8443;

        Some(ParsedPacket {
            src_addr: Some(SocketAddr::V4(SocketAddrV4::new(src_ip, src_port))),
            dst_addr: Some(SocketAddr::V4(SocketAddrV4::new(dst_ip, dst_port))),
            protocol,
            payload_offset: udp_offset + 8,
            is_udp: true,
            is_tunnel,
        })
    }

    /// Batch parse with prefetching
    #[inline]
    pub fn parse_batch(packets: &[&[u8]], results: &mut Vec<Option<ParsedPacket>>) {
        results.clear();
        results.reserve(packets.len());

        for i in 0..packets.len() {
            if i + 1 < packets.len() {
                Self::prefetch(packets[i + 1]);
            }
            results.push(Self::parse_fast(packets[i]));
        }
    }

    #[inline(always)]
    fn prefetch(data: &[u8]) {
        #[cfg(target_arch = "x86_64")]
        unsafe {
            if data.len() >= 64 {
                std::arch::x86_64::_mm_prefetch(
                    data.as_ptr() as *const i8,
                    std::arch::x86_64::_MM_HINT_T0,
                );
            }
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            if data.len() >= 64 {
                std::arch::aarch64::_prefetch(data.as_ptr() as *const i8, 0, 3);
            }
        }
    }
}

// =============================================================================
// Security Utilities
// =============================================================================

pub mod security {
    use super::*;

    /// Constant-time memory comparison (prevents timing attacks)
    #[inline]
    pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut result: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
    }

    #[derive(Debug, Clone, Copy, PartialEq)]
    pub enum ValidationResult {
        Valid,
        TooShort,
        TooLong,
        InvalidEthertype,
        InvalidIpVersion,
        InvalidIpHeaderLen,
        InvalidLength,
        ZeroTtl,
    }

    /// Validate packet structure
    #[inline]
    pub fn validate_packet(data: &[u8]) -> ValidationResult {
        if data.len() < 42 {
            return ValidationResult::TooShort;
        }
        if data.len() > 9728 {
            return ValidationResult::TooLong;
        }

        let ethertype = u16::from_be_bytes([data[12], data[13]]);
        if ethertype != 0x0800 && ethertype != 0x86DD {
            return ValidationResult::InvalidEthertype;
        }

        let ip_version = data[14] >> 4;
        if ip_version != 4 && ip_version != 6 {
            return ValidationResult::InvalidIpVersion;
        }

        if ip_version == 4 {
            let ihl = (data[14] & 0x0F) as usize * 4;
            if !(20..=60).contains(&ihl) {
                return ValidationResult::InvalidIpHeaderLen;
            }

            let total_len = u16::from_be_bytes([data[16], data[17]]) as usize;
            if total_len > data.len() - 14 {
                return ValidationResult::InvalidLength;
            }

            if data[22] == 0 {
                return ValidationResult::ZeroTtl;
            }
        }

        ValidationResult::Valid
    }

    /// Rate limiter with token bucket algorithm
    pub struct RateLimiter {
        tokens: AtomicU64,
        last_update: AtomicU64,
        rate: u64,
        burst: u64,
    }

    impl RateLimiter {
        pub fn new(rate: u64, burst: u64) -> Self {
            Self {
                tokens: AtomicU64::new(burst),
                last_update: AtomicU64::new(Self::now_ns()),
                rate,
                burst,
            }
        }

        #[inline]
        pub fn allow(&self) -> bool {
            self.allow_n(1)
        }

        #[inline]
        pub fn allow_n(&self, n: u64) -> bool {
            let now = Self::now_ns();
            let last = self.last_update.load(Ordering::Relaxed);
            let elapsed_ns = now.saturating_sub(last);
            let new_tokens = (elapsed_ns * self.rate) / 1_000_000_000;
            let current = self.tokens.load(Ordering::Relaxed);
            let available = std::cmp::min(current + new_tokens, self.burst);

            if available >= n
                && self
                    .tokens
                    .compare_exchange(current, available - n, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                self.last_update.store(now, Ordering::Relaxed);
                return true;
            }
            false
        }

        #[inline(always)]
        fn now_ns() -> u64 {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        }
    }
}

// =============================================================================
// Backward Compatibility Types (from kernel_bypass.rs)
// =============================================================================

/// Bypass configuration
#[derive(Debug, Clone)]
pub struct BypassConfig {
    pub pci_address: String,
    pub rx_queues: u16,
    pub tx_queues: u16,
    pub rx_ring_size: u16,
    pub tx_ring_size: u16,
    pub mempool_size: u32,
    pub mempool_cache_size: u32,
    pub mtu: u16,
    pub enable_rss: bool,
    pub port: u16,
    pub hugepages: u32,
}

impl Default for BypassConfig {
    fn default() -> Self {
        Self {
            pci_address: String::new(),
            rx_queues: 4,
            tx_queues: 4,
            rx_ring_size: 4096,
            tx_ring_size: 4096,
            mempool_size: 65536,
            mempool_cache_size: 512,
            mtu: 9000,
            enable_rss: true,
            port: 51820,
            hugepages: 1024,
        }
    }
}

/// Bypass packet wrapper
#[derive(Debug)]
pub struct BypassPacket {
    pub data: Vec<u8>,
    pub len: usize,
    pub src_addr: Option<SocketAddr>,
    pub dst_addr: Option<SocketAddr>,
    pub timestamp: Instant,
    pub queue_id: u16,
}

impl BypassPacket {
    pub fn new(data: Vec<u8>, queue_id: u16) -> Self {
        let len = data.len();
        Self {
            data,
            len,
            src_addr: None,
            dst_addr: None,
            timestamp: Instant::now(),
            queue_id,
        }
    }

    pub fn parse_headers(&mut self) -> bool {
        if let Some(parsed) = PacketParser::parse_fast(&self.data) {
            self.src_addr = parsed.src_addr;
            self.dst_addr = parsed.dst_addr;
            true
        } else {
            false
        }
    }
}

/// Bypass processor (stub for compatibility)
pub struct BypassProcessor {
    running: Arc<AtomicBool>,
}

impl BypassProcessor {
    pub fn new(_config: BypassConfig) -> std::io::Result<Self> {
        Ok(Self {
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn is_available() -> bool {
        #[cfg(target_os = "linux")]
        {
            std::path::Path::new("/dev/vfio").exists()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    pub fn start(&self) {
        self.running.store(true, Ordering::SeqCst);
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Bypass mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BypassMode {
    Userspace,
    Disabled,
}

/// Unified bypass interface
pub struct UnifiedBypass {
    mode: BypassMode,
    running: Arc<AtomicBool>,
}

impl UnifiedBypass {
    #[cfg(target_os = "linux")]
    pub fn new(_interface: Option<&str>) -> std::io::Result<Self> {
        Ok(Self {
            mode: BypassMode::Userspace,
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new(_interface: Option<&str>) -> std::io::Result<Self> {
        Ok(Self {
            mode: BypassMode::Disabled,
            running: Arc::new(AtomicBool::new(false)),
        })
    }

    pub fn mode(&self) -> BypassMode {
        self.mode
    }

    pub fn is_kernel_bypass(&self) -> bool {
        self.mode == BypassMode::Userspace
    }

    pub fn start<F>(&mut self, _handler: F) -> std::io::Result<()>
    where
        F: Fn(&[u8]) -> Option<Vec<u8>> + Send + Sync + Clone + 'static,
    {
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    pub fn stop(&mut self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn stats_summary(&self) -> String {
        if self.mode == BypassMode::Userspace {
            "Unified bypass: userspace mode".to_string()
        } else {
            "Kernel bypass disabled".to_string()
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spsc_ring_basic() {
        let ring = SpscRing::<u32>::new(16);
        assert!(ring.is_empty());

        assert!(ring.push(1));
        assert!(ring.push(2));
        assert_eq!(ring.len(), 2);

        assert_eq!(ring.pop(), Some(1));
        assert_eq!(ring.pop(), Some(2));
        assert!(ring.is_empty());
    }

    #[test]
    fn test_packet_buffer() {
        let mut buf = PacketBuffer::new();
        buf.set_data(&[1, 2, 3, 4, 5]);
        assert_eq!(buf.len(), 5);
        assert_eq!(buf.data(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_aligned_counter() {
        let counter = AlignedCounter::new(0);
        counter.inc();
        counter.add(5);
        assert_eq!(counter.get(), 6);
    }

    #[test]
    fn test_security_validation() {
        let mut packet = vec![0u8; 50];
        packet[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        packet[14] = 0x45;
        packet[16..18].copy_from_slice(&36u16.to_be_bytes());
        packet[22] = 64;

        assert_eq!(
            security::validate_packet(&packet),
            security::ValidationResult::Valid
        );
        assert_eq!(
            security::validate_packet(&[0; 20]),
            security::ValidationResult::TooShort
        );
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(security::constant_time_compare(&[1, 2, 3], &[1, 2, 3]));
        assert!(!security::constant_time_compare(&[1, 2, 3], &[1, 2, 4]));
    }
}
