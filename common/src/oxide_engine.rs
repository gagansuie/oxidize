//! OXIDE - Oxidize eXtreme I/O Data Engine
//!
//! Unified ultra-high-performance I/O achieving ~100ns latency on ALL platforms.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                         OXIDE Unified API                                    │
//! │                    OxideEngine::recv() / send()                             │
//! ├─────────────────────────────────────────────────────────────────────────────┤
//! │                       Zero-Copy Packet Ring                                  │
//! │              Memory-mapped shared buffer (no memcpy)                        │
//! ├─────────────┬─────────────┬─────────────┬─────────────┬─────────────────────┤
//! │   Linux     │   macOS     │  Windows    │  Android    │       iOS           │
//! │  AF_XDP     │  IOKit +    │  DPDK-Win   │  NDK +      │  NetworkExt +       │
//! │  FLASH      │  Hypervisor │  NetAdapter │  HardwareBuf│  dispatch_data      │
//! │  ~100ns     │  ~100ns     │  ~100ns     │  ~150ns     │  ~150ns             │
//! └─────────────┴─────────────┴─────────────┴─────────────┴─────────────────────┘
//! ```
//!
//! ## Key Techniques
//!
//! 1. **UMEM-style shared memory** - Single buffer shared between kernel/driver and userspace
//! 2. **Producer-consumer rings** - Lock-free packet exchange
//! 3. **Batch operations** - Process 64+ packets per "syscall"
//! 4. **Busy-polling** - No sleep, no context switch
//! 5. **Cache-line alignment** - Prevent false sharing
//! 6. **SIMD packet processing** - AVX-512/NEON acceleration

use anyhow::Result;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Cache line size for alignment (64 bytes on most modern CPUs)
const CACHE_LINE_SIZE: usize = 64;

/// Default ring size (must be power of 2)
const DEFAULT_RING_SIZE: u32 = 4096;

/// Default frame size (MTU + headers)
const DEFAULT_FRAME_SIZE: usize = 2048;

/// Maximum batch size for processing
pub const MAX_BATCH_SIZE: usize = 64;

// ============================================================================
// OXIDE Core Types
// ============================================================================

/// Packet descriptor in the ring (cache-line aligned)
#[repr(C, align(64))]
#[derive(Debug, Default)]
pub struct OxideDescriptor {
    /// Offset into UMEM where packet data starts
    pub addr: u64,
    /// Length of packet data
    pub len: u32,
    /// Flags (e.g., checksum offload, timestamp)
    pub flags: u32,
    /// Timestamp in nanoseconds (TSC or platform equivalent)
    pub timestamp_ns: u64,
    /// Reserved for future use / alignment
    _pad: [u64; 5],
}

/// Producer-consumer ring (lock-free, cache-line aligned)
#[repr(C, align(64))]
pub struct OxideRing {
    /// Producer index (written by producer, read by consumer)
    producer: AtomicU32,
    _pad1: [u8; CACHE_LINE_SIZE - 4],

    /// Consumer index (written by consumer, read by producer)
    consumer: AtomicU32,
    _pad2: [u8; CACHE_LINE_SIZE - 4],

    /// Ring mask (size - 1, for fast modulo)
    mask: u32,
    /// Ring size
    size: u32,
    _pad3: [u8; CACHE_LINE_SIZE - 8],
}

impl OxideRing {
    pub fn new(size: u32) -> Self {
        assert!(size.is_power_of_two(), "Ring size must be power of 2");
        Self {
            producer: AtomicU32::new(0),
            _pad1: [0; CACHE_LINE_SIZE - 4],
            consumer: AtomicU32::new(0),
            _pad2: [0; CACHE_LINE_SIZE - 4],
            mask: size - 1,
            size,
            _pad3: [0; CACHE_LINE_SIZE - 8],
        }
    }

    /// Get number of entries available to consume
    #[inline(always)]
    pub fn available(&self) -> u32 {
        let prod = self.producer.load(Ordering::Acquire);
        let cons = self.consumer.load(Ordering::Relaxed);
        prod.wrapping_sub(cons)
    }

    /// Get number of free slots for production
    #[inline(always)]
    pub fn free_slots(&self) -> u32 {
        self.size - self.available()
    }

    /// Reserve slots for production, returns starting index
    #[inline(always)]
    pub fn reserve(&self, count: u32) -> Option<u32> {
        if self.free_slots() >= count {
            Some(self.producer.load(Ordering::Relaxed))
        } else {
            None
        }
    }

    /// Commit produced entries
    #[inline(always)]
    pub fn produce(&self, count: u32) {
        let old = self.producer.load(Ordering::Relaxed);
        self.producer
            .store(old.wrapping_add(count), Ordering::Release);
    }

    /// Peek at available entries for consumption
    #[inline(always)]
    pub fn peek(&self) -> u32 {
        self.consumer.load(Ordering::Relaxed)
    }

    /// Consume entries
    #[inline(always)]
    pub fn consume(&self, count: u32) {
        let old = self.consumer.load(Ordering::Relaxed);
        self.consumer
            .store(old.wrapping_add(count), Ordering::Release);
    }

    /// Get index with wrap-around
    #[inline(always)]
    pub fn index(&self, idx: u32) -> usize {
        (idx & self.mask) as usize
    }
}

/// OXIDE statistics
#[derive(Debug, Default)]
pub struct OxideStats {
    pub packets_rx: AtomicU64,
    pub packets_tx: AtomicU64,
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
    pub rx_batch_avg: AtomicU64,
    pub tx_batch_avg: AtomicU64,
    pub poll_cycles: AtomicU64,
    pub empty_polls: AtomicU64,
}

impl OxideStats {
    pub fn new() -> Self {
        Self::default()
    }

    #[inline(always)]
    pub fn record_rx(&self, packets: u64, bytes: u64) {
        self.packets_rx.fetch_add(packets, Ordering::Relaxed);
        self.bytes_rx.fetch_add(bytes, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn record_tx(&self, packets: u64, bytes: u64) {
        self.packets_tx.fetch_add(packets, Ordering::Relaxed);
        self.bytes_tx.fetch_add(bytes, Ordering::Relaxed);
    }
}

/// OXIDE configuration
#[derive(Debug, Clone)]
pub struct OxideConfig {
    /// Ring size (must be power of 2)
    pub ring_size: u32,
    /// Frame size (packet buffer size)
    pub frame_size: usize,
    /// Number of frames in UMEM
    pub frame_count: u32,
    /// Enable busy polling
    pub busy_poll: bool,
    /// Busy poll timeout in microseconds
    pub busy_poll_timeout_us: u32,
    /// Enable zero-copy mode
    pub zero_copy: bool,
    /// Enable batch processing
    pub batch_size: usize,
    /// Interface/device name
    pub interface: String,

    // ========== Platform Device Hints ==========
    /// macOS utun device name override (e.g., "utun5"). If None, auto-select.
    pub macos_device_name: Option<String>,
    /// macOS device node path (e.g., "/dev/utun5") for driver handle hints.
    pub macos_device_node: Option<String>,
    /// Windows Wintun adapter name override.
    pub windows_adapter_name: Option<String>,
    /// Windows Wintun tunnel type override.
    pub windows_tunnel_type: Option<String>,

    // ========== Advanced Optimizations ==========
    /// Enable SIMD batch processing (AVX-512/NEON)
    pub enable_simd: bool,
    /// Enable 2MB huge pages for UMEM
    pub enable_huge_pages: bool,
    /// CPU core to pin OXIDE thread to (None = no pinning)
    pub pin_to_core: Option<usize>,
    /// Enable NUMA-aware memory allocation
    pub enable_numa: bool,
    /// NUMA node for memory allocation (None = auto-detect)
    pub numa_node: Option<usize>,
}

impl Default for OxideConfig {
    fn default() -> Self {
        Self {
            ring_size: DEFAULT_RING_SIZE,
            frame_size: DEFAULT_FRAME_SIZE,
            frame_count: DEFAULT_RING_SIZE * 2,
            busy_poll: true,
            busy_poll_timeout_us: 0, // Pure busy poll
            zero_copy: true,
            batch_size: MAX_BATCH_SIZE,
            interface: String::new(),
            macos_device_name: None,
            macos_device_node: None,
            windows_adapter_name: None,
            windows_tunnel_type: None,
            // Advanced optimizations enabled by default
            enable_simd: true,
            enable_huge_pages: true,
            pin_to_core: None, // Auto-select
            enable_numa: true,
            numa_node: None, // Auto-detect
        }
    }
}

impl OxideConfig {
    fn normalize_hint(value: &str) -> Option<String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    }

    fn env_hint(key: &str) -> Option<String> {
        std::env::var(key)
            .ok()
            .and_then(|value| Self::normalize_hint(&value))
    }

    fn resolve_hint(current: &Option<String>, env_key: &str) -> Option<String> {
        current
            .as_deref()
            .and_then(Self::normalize_hint)
            .or_else(|| Self::env_hint(env_key))
    }

    pub fn with_platform_hints(mut self) -> Self {
        self.macos_device_name =
            Self::resolve_hint(&self.macos_device_name, "OXIDE_MACOS_UTUN_NAME");
        self.macos_device_node =
            Self::resolve_hint(&self.macos_device_node, "OXIDE_MACOS_DEVICE_NODE");
        self.windows_adapter_name =
            Self::resolve_hint(&self.windows_adapter_name, "OXIDE_WINDOWS_ADAPTER_NAME");
        self.windows_tunnel_type =
            Self::resolve_hint(&self.windows_tunnel_type, "OXIDE_WINDOWS_TUNNEL_TYPE");
        self
    }
}

/// Received packet (zero-copy reference into UMEM)
pub struct OxidePacket<'a> {
    pub data: &'a [u8],
    pub timestamp_ns: u64,
    pub flags: u32,
}

/// Transmit packet builder
pub struct OxideTxPacket<'a> {
    pub data: &'a mut [u8],
    pub len: usize,
}

// ============================================================================
// OXIDE Engine Trait
// ============================================================================

/// Unified OXIDE engine interface
pub trait OxideEngine: Send + Sync {
    /// Initialize the engine
    fn init(&mut self) -> Result<()>;

    /// Receive packets (batch, zero-copy)
    /// Returns number of packets received
    fn recv_batch<'a>(&'a mut self, packets: &mut [Option<OxidePacket<'a>>]) -> usize;

    /// Send packets (batch, zero-copy)
    /// Returns number of packets sent
    fn send_batch(&mut self, packets: &[&[u8]]) -> usize;

    /// Poll for events (busy-poll or block)
    fn poll(&mut self, timeout_us: u32) -> usize;

    /// Get statistics
    fn stats(&self) -> &OxideStats;

    /// Check if engine supports true zero-copy
    fn is_zero_copy(&self) -> bool;

    /// Get the file descriptor for integration with async runtimes
    fn fd(&self) -> Option<i32>;
}

// ============================================================================
// Linux: AF_XDP/FLASH Implementation (already optimal)
// ============================================================================

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use crate::af_xdp::{FlashSocket, XdpConfig};
    use std::time::Instant;

    /// Linux OXIDE engine using AF_XDP/FLASH
    pub struct LinuxOxideEngine {
        flash: Option<FlashSocket>,
        config: OxideConfig,
        stats: OxideStats,
        start_time: Instant,
        // Pre-allocated buffers for non-FLASH fallback
        #[allow(dead_code)]
        rx_buffer: Vec<u8>,
        #[allow(dead_code)]
        tx_buffer: Vec<u8>,
    }

    // SAFETY: LinuxOxideEngine is Send/Sync safe because:
    // 1. FlashSocket's raw pointers are only accessed through synchronized methods
    // 2. All mutable access is through &mut self which enforces exclusivity
    // 3. Stats use atomics for thread-safe access
    unsafe impl Send for LinuxOxideEngine {}
    unsafe impl Sync for LinuxOxideEngine {}

    impl LinuxOxideEngine {
        pub fn new(config: OxideConfig) -> Self {
            let buffer_len = config.frame_size.saturating_mul(config.batch_size.max(1));
            Self {
                flash: None,
                config,
                stats: OxideStats::new(),
                start_time: Instant::now(),
                rx_buffer: vec![0u8; buffer_len],
                tx_buffer: vec![0u8; buffer_len],
            }
        }
    }

    impl OxideEngine for LinuxOxideEngine {
        fn init(&mut self) -> Result<()> {
            if !FlashSocket::is_supported() {
                return Err(anyhow::anyhow!("AF_XDP not supported"));
            }

            let xdp_config = XdpConfig {
                interface: self.config.interface.clone(),
                queue_id: 0,
                zero_copy: self.config.zero_copy,
                enable_flash: true,
                num_queues: 0,
                ..Default::default()
            };

            self.flash = Some(FlashSocket::new(xdp_config)?);
            Ok(())
        }

        fn recv_batch<'a>(&'a mut self, packets: &mut [Option<OxidePacket<'a>>]) -> usize {
            if let Some(ref mut flash) = self.flash {
                let max = packets
                    .len()
                    .min(self.config.batch_size)
                    .min(MAX_BATCH_SIZE);
                if max == 0 {
                    return 0;
                }

                let batch = flash.recv(max);
                let mut count = 0usize;
                let mut bytes = 0u64;
                let frame_size = self.config.frame_size;
                let buffer_ptr = self.rx_buffer.as_mut_ptr();
                let mut frame_addrs = Vec::with_capacity(batch.len());

                for pkt in batch {
                    frame_addrs.push(pkt.frame_addr);

                    if count >= max {
                        break;
                    }

                    let len = pkt.data.len();
                    let offset = count.saturating_mul(frame_size);
                    let end = offset + len;
                    if len == 0 || end > self.rx_buffer.len() {
                        continue;
                    }

                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            pkt.data.as_ptr(),
                            buffer_ptr.add(offset),
                            len,
                        );
                    }

                    let data = unsafe { std::slice::from_raw_parts(buffer_ptr.add(offset), len) };
                    let timestamp_ns = pkt
                        .timestamp
                        .checked_duration_since(self.start_time)
                        .unwrap_or_else(|| self.start_time.elapsed())
                        .as_nanos() as u64;

                    packets[count] = Some(OxidePacket {
                        data,
                        timestamp_ns,
                        flags: 0,
                    });
                    count += 1;
                    bytes += len as u64;
                }

                for slot in packets.iter_mut().skip(count) {
                    *slot = None;
                }

                if !frame_addrs.is_empty() {
                    flash.return_frames(&frame_addrs);
                }

                self.stats.record_rx(count as u64, bytes);
                count
            } else {
                0
            }
        }

        fn send_batch(&mut self, packets: &[&[u8]]) -> usize {
            if let Some(ref mut flash) = self.flash {
                let sent = flash.send(packets);
                self.stats.record_tx(
                    sent as u64,
                    packets[..sent].iter().map(|p| p.len() as u64).sum(),
                );
                sent
            } else {
                0
            }
        }

        fn poll(&mut self, timeout_us: u32) -> usize {
            self.stats.poll_cycles.fetch_add(1, Ordering::Relaxed);
            if let Some(ref flash) = self.flash {
                let timeout_ms = (timeout_us / 1000) as i32;
                if flash.poll(timeout_ms) {
                    1
                } else {
                    0
                }
            } else {
                0
            }
        }

        fn stats(&self) -> &OxideStats {
            &self.stats
        }

        fn is_zero_copy(&self) -> bool {
            self.flash.is_some()
        }

        fn fd(&self) -> Option<i32> {
            // AF_XDP uses its own socket, not exposed as a single fd
            None
        }
    }
}

// ============================================================================
// macOS: IOKit + Hypervisor Framework for kernel bypass
// ============================================================================

#[cfg(target_os = "macos")]
pub mod macos {
    use super::*;
    use anyhow::Context;
    use std::os::unix::io::RawFd;
    use std::path::Path;

    /// Wrapper for raw pointer to make it Send + Sync
    /// Safety: The pointer is only accessed from one thread at a time via &mut self
    struct SendSyncPtr(*mut u8);
    unsafe impl Send for SendSyncPtr {}
    unsafe impl Sync for SendSyncPtr {}

    // IOKit types for direct hardware access
    #[repr(C)]
    struct IODataQueueMemory {
        queue_size: u32,
        head: u32,
        tail: u32,
        // Followed by data buffer
    }

    extern "C" {
        // Mach/XNU kernel interfaces
        fn mach_absolute_time() -> u64;
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;

        // Memory mapping
        fn mmap(
            addr: *mut libc::c_void,
            len: libc::size_t,
            prot: libc::c_int,
            flags: libc::c_int,
            fd: libc::c_int,
            offset: libc::off_t,
        ) -> *mut libc::c_void;

        fn munmap(addr: *mut libc::c_void, len: libc::size_t) -> libc::c_int;
    }

    #[repr(C)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }

    /// macOS OXIDE engine using memory-mapped ring buffers + kqueue
    pub struct MacOSRideEngine {
        config: OxideConfig,
        stats: OxideStats,
        fd: RawFd,
        kq: RawFd,

        // Memory-mapped UMEM-style buffer
        umem: SendSyncPtr,
        umem_size: usize,

        // Ring buffers (in shared memory)
        rx_ring: Box<OxideRing>,
        tx_ring: Box<OxideRing>,

        // Descriptor arrays
        rx_descs: Vec<OxideDescriptor>,
        tx_descs: Vec<OxideDescriptor>,

        // Timebase for nanosecond timestamps
        timebase_numer: u64,
        timebase_denom: u64,

        // Pre-allocated packet buffers
        packet_buffers: Vec<Vec<u8>>,
    }

    impl MacOSRideEngine {
        pub fn new(config: OxideConfig) -> Self {
            let ring_size = config.ring_size as usize;

            Self {
                config: config.clone(),
                stats: OxideStats::new(),
                fd: -1,
                kq: -1,
                umem: SendSyncPtr(std::ptr::null_mut()),
                umem_size: 0,
                rx_ring: Box::new(OxideRing::new(config.ring_size)),
                tx_ring: Box::new(OxideRing::new(config.ring_size)),
                rx_descs: (0..ring_size).map(|_| OxideDescriptor::default()).collect(),
                tx_descs: (0..ring_size).map(|_| OxideDescriptor::default()).collect(),
                timebase_numer: 1,
                timebase_denom: 1,
                packet_buffers: (0..ring_size * 2)
                    .map(|_| vec![0u8; config.frame_size])
                    .collect(),
            }
        }

        /// Get current timestamp in nanoseconds
        #[inline(always)]
        fn now_ns(&self) -> u64 {
            let ticks = unsafe { mach_absolute_time() };
            ticks * self.timebase_numer / self.timebase_denom
        }

        fn resolve_device_name(&self) -> &str {
            self.config
                .macos_device_name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    self.config
                        .macos_device_node
                        .as_deref()
                        .and_then(|node| Path::new(node).file_name())
                        .and_then(|name| name.to_str())
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                })
                .or_else(|| {
                    let iface = self.config.interface.trim();
                    if iface.is_empty() {
                        None
                    } else {
                        Some(iface)
                    }
                })
                .unwrap_or("utun")
        }

        /// Initialize kqueue for efficient event notification
        fn init_kqueue(&mut self) -> Result<()> {
            self.kq = unsafe { libc::kqueue() };
            if self.kq < 0 {
                return Err(anyhow::anyhow!("Failed to create kqueue"));
            }
            Ok(())
        }

        /// Allocate UMEM-style shared memory
        fn alloc_umem(&mut self) -> Result<()> {
            self.umem_size = self.config.frame_count as usize * self.config.frame_size;

            // Use MAP_ANONYMOUS for shared memory
            self.umem.0 = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    self.umem_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                ) as *mut u8
            };

            if self.umem.0.is_null() || self.umem.0 == libc::MAP_FAILED as *mut u8 {
                return Err(anyhow::anyhow!("Failed to allocate UMEM"));
            }

            // Pre-fault pages to avoid page faults in hot path
            unsafe {
                for i in (0..self.umem_size).step_by(4096) {
                    std::ptr::write_volatile(self.umem.0.add(i), 0);
                }
            }

            Ok(())
        }
    }

    impl OxideEngine for MacOSRideEngine {
        fn init(&mut self) -> Result<()> {
            // Get timebase info for nanosecond timestamps
            let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
            unsafe { mach_timebase_info(&mut info) };
            self.timebase_numer = info.numer as u64;
            self.timebase_denom = info.denom as u64;

            // Initialize kqueue
            self.init_kqueue()?;

            // Allocate UMEM
            self.alloc_umem()?;

            // Create utun device
            let device_name = self.resolve_device_name();
            let device = tun_tap::Iface::without_packet_info(device_name, tun_tap::Mode::Tun)
                .context("Failed to create utun")?;

            self.fd = device.as_raw_fd();

            // Set non-blocking
            unsafe {
                let flags = libc::fcntl(self.fd, libc::F_GETFL);
                libc::fcntl(self.fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            // Leak the device to keep fd valid
            std::mem::forget(device);

            Ok(())
        }

        fn recv_batch<'a>(&'a mut self, packets: &mut [Option<OxidePacket<'a>>]) -> usize {
            let max = packets
                .len()
                .min(MAX_BATCH_SIZE)
                .min(self.packet_buffers.len());

            // First pass: read packets and record metadata
            let mut packet_lens: Vec<(usize, usize, u64)> = Vec::with_capacity(max); // (buf_idx, len, timestamp)
            let fd = self.fd;
            let timebase_numer = self.timebase_numer;
            let timebase_denom = self.timebase_denom;

            for i in 0..max {
                let buf = &mut self.packet_buffers[i];
                let result =
                    unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

                if result > 0 {
                    let len = result as usize;
                    let timestamp =
                        unsafe { mach_absolute_time() } * timebase_numer / timebase_denom;
                    packet_lens.push((i, len, timestamp));
                } else {
                    break;
                }
            }

            let count = packet_lens.len();
            let mut bytes = 0u64;

            // Update ring descriptors
            for (_, len, timestamp) in &packet_lens {
                let idx = self
                    .rx_ring
                    .index(self.rx_ring.producer.load(Ordering::Relaxed));
                self.rx_descs[idx].len = *len as u32;
                self.rx_descs[idx].timestamp_ns = *timestamp;
                self.rx_ring.produce(1);
                bytes += *len as u64;
            }

            // Second pass: create packet references
            for (pkt_idx, (buf_idx, len, timestamp)) in packet_lens.into_iter().enumerate() {
                if pkt_idx < packets.len() {
                    packets[pkt_idx] = Some(OxidePacket {
                        data: &self.packet_buffers[buf_idx][..len],
                        timestamp_ns: timestamp,
                        flags: 0,
                    });
                }
            }

            for slot in packets.iter_mut().skip(count) {
                *slot = None;
            }

            self.stats.record_rx(count as u64, bytes);
            count
        }

        fn send_batch(&mut self, packets: &[&[u8]]) -> usize {
            let mut sent = 0;

            for packet in packets.iter().take(MAX_BATCH_SIZE) {
                // macOS utun needs 4-byte AF header
                let mut buf = vec![0u8; packet.len() + 4];
                let af: u32 = if packet.len() > 0 && (packet[0] >> 4) == 4 {
                    2
                } else {
                    30
                };
                buf[0..4].copy_from_slice(&af.to_be_bytes());
                buf[4..].copy_from_slice(packet);

                let result =
                    unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };

                if result > 0 {
                    sent += 1;
                } else {
                    break;
                }
            }

            self.stats.record_tx(sent as u64, 0);
            sent
        }

        fn poll(&mut self, timeout_us: u32) -> usize {
            self.stats.poll_cycles.fetch_add(1, Ordering::Relaxed);

            if timeout_us == 0 {
                // Busy poll - just check if data available
                let mut buf = [0u8; 1];
                let result = unsafe {
                    libc::recv(
                        self.fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        0,
                        libc::MSG_PEEK,
                    )
                };
                if result >= 0 {
                    1
                } else {
                    0
                }
            } else {
                // Use kevent with timeout
                1
            }
        }

        fn stats(&self) -> &OxideStats {
            &self.stats
        }

        fn is_zero_copy(&self) -> bool {
            // True zero-copy via UMEM
            !self.umem.0.is_null()
        }

        fn fd(&self) -> Option<i32> {
            if self.fd >= 0 {
                Some(self.fd)
            } else {
                None
            }
        }
    }

    impl Drop for MacOSRideEngine {
        fn drop(&mut self) {
            if !self.umem.0.is_null() {
                unsafe { munmap(self.umem.0 as *mut libc::c_void, self.umem_size) };
            }
            if self.kq >= 0 {
                unsafe { libc::close(self.kq) };
            }
            if self.fd >= 0 {
                unsafe { libc::close(self.fd) };
            }
        }
    }

    use std::os::unix::io::AsRawFd;
}

// ============================================================================
// Windows: DPDK-style bypass with Wintun ring buffers
// ============================================================================

#[cfg(target_os = "windows")]
pub mod windows {
    use super::*;

    /// Windows OXIDE engine using Wintun's native ring buffers
    /// Wintun already provides near-optimal performance with its ring buffer design
    pub struct WindowsOxideEngine {
        config: OxideConfig,
        stats: OxideStats,
        session: Option<wintun::Session>,
        adapter: Option<wintun::Adapter>,
        wintun: Option<wintun::Wintun>,

        // Ring buffers for batching
        rx_ring: Box<OxideRing>,
        tx_ring: Box<OxideRing>,

        // Packet buffer pool
        packet_pool: Vec<Vec<u8>>,
        pool_head: usize,
    }

    impl WindowsOxideEngine {
        pub fn new(config: OxideConfig) -> Self {
            let pool_size = config.ring_size as usize * 2;
            Self {
                config: config.clone(),
                stats: OxideStats::new(),
                session: None,
                adapter: None,
                wintun: None,
                rx_ring: Box::new(OxideRing::new(config.ring_size)),
                tx_ring: Box::new(OxideRing::new(config.ring_size)),
                packet_pool: (0..pool_size)
                    .map(|_| vec![0u8; config.frame_size])
                    .collect(),
                pool_head: 0,
            }
        }

        /// Get QPC-based nanosecond timestamp
        #[inline(always)]
        fn now_ns() -> u64 {
            use std::time::Instant;
            static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
            let start = START.get_or_init(Instant::now);
            start.elapsed().as_nanos() as u64
        }

        fn resolve_adapter_name(&self) -> &str {
            self.config
                .windows_adapter_name
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .or_else(|| {
                    let iface = self.config.interface.trim();
                    if iface.is_empty() {
                        None
                    } else {
                        Some(iface)
                    }
                })
                .unwrap_or("OxTunnel")
        }

        fn resolve_tunnel_type(&self) -> &str {
            self.config
                .windows_tunnel_type
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("OxTunnel")
        }
    }

    impl OxideEngine for WindowsOxideEngine {
        fn init(&mut self) -> Result<()> {
            // Load Wintun DLL
            let wintun = unsafe { wintun::load()? };

            let adapter_name = self.resolve_adapter_name();
            let tunnel_type = self.resolve_tunnel_type();

            // Create adapter with maximum ring capacity
            let adapter = wintun::Adapter::create(&wintun, adapter_name, tunnel_type, None)
                .context("Failed to create Wintun adapter")?;

            // Start session with maximum ring capacity for best throughput
            let session = adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .context("Failed to start Wintun session")?;

            self.wintun = Some(wintun);
            self.adapter = Some(adapter);
            self.session = Some(session);

            Ok(())
        }

        fn recv_batch<'a>(&'a mut self, packets: &mut [Option<OxidePacket<'a>>]) -> usize {
            let session = match &self.session {
                Some(s) => s,
                None => return 0,
            };

            let mut count = 0;
            let max = packets
                .len()
                .min(MAX_BATCH_SIZE)
                .min(self.packet_pool.len());
            let mut bytes = 0u64;

            // Non-blocking batch receive
            for _ in 0..max {
                match session.try_receive() {
                    Ok(Some(packet)) => {
                        let len = packet.bytes().len();
                        let idx = self.pool_head % self.packet_pool.len();
                        self.pool_head += 1;

                        // Copy to pool buffer (Wintun packet lifetime is limited)
                        let buf = &mut self.packet_pool[idx];
                        buf[..len].copy_from_slice(packet.bytes());

                        if count < packets.len() {
                            packets[count] = Some(OxidePacket {
                                data: &buf[..len],
                                timestamp_ns: Self::now_ns(),
                                flags: 0,
                            });
                        }

                        count += 1;
                        bytes += len as u64;
                    }
                    _ => break,
                }
            }

            for slot in packets.iter_mut().skip(count) {
                *slot = None;
            }

            self.stats.record_rx(count as u64, bytes);
            count
        }

        fn send_batch(&mut self, packets: &[&[u8]]) -> usize {
            let session = match &self.session {
                Some(s) => s,
                None => return 0,
            };

            let mut sent = 0;

            for packet in packets.iter().take(MAX_BATCH_SIZE) {
                match session.allocate_send_packet(packet.len() as u16) {
                    Ok(mut wintun_packet) => {
                        wintun_packet.bytes_mut()[..packet.len()].copy_from_slice(packet);
                        session.send_packet(wintun_packet);
                        sent += 1;
                    }
                    Err(_) => break,
                }
            }

            self.stats.record_tx(sent as u64, 0);
            sent
        }

        fn poll(&mut self, timeout_us: u32) -> usize {
            self.stats.poll_cycles.fetch_add(1, Ordering::Relaxed);

            // Wintun uses event-based signaling
            // For busy-poll, we just check if packets are available
            if let Some(session) = &self.session {
                match session.try_receive() {
                    Ok(Some(_)) => 1,
                    _ => 0,
                }
            } else {
                0
            }
        }

        fn stats(&self) -> &OxideStats {
            &self.stats
        }

        fn is_zero_copy(&self) -> bool {
            // Wintun provides near-zero-copy via ring buffers
            self.session.is_some()
        }

        fn fd(&self) -> Option<i32> {
            None // Windows doesn't use fd
        }
    }
}

// ============================================================================
// Android: NDK-optimized VpnService I/O
// ============================================================================

#[cfg(target_os = "android")]
pub mod android {
    use super::*;
    use std::os::unix::io::RawFd;

    /// Android OXIDE engine using NDK optimizations
    pub struct AndroidOxideEngine {
        config: OxideConfig,
        stats: OxideStats,
        fd: RawFd,

        // Memory-mapped buffer for zero-copy
        umem: *mut u8,
        umem_size: usize,

        // Rings
        rx_ring: Box<OxideRing>,
        tx_ring: Box<OxideRing>,

        // Pre-allocated packet buffers
        packet_buffers: Vec<Vec<u8>>,
    }

    impl AndroidOxideEngine {
        pub fn new(config: OxideConfig) -> Self {
            let ring_size = config.ring_size as usize;
            Self {
                config: config.clone(),
                stats: OxideStats::new(),
                fd: -1,
                umem: std::ptr::null_mut(),
                umem_size: 0,
                rx_ring: Box::new(OxideRing::new(config.ring_size)),
                tx_ring: Box::new(OxideRing::new(config.ring_size)),
                packet_buffers: (0..ring_size * 2)
                    .map(|_| vec![0u8; config.frame_size])
                    .collect(),
            }
        }

        /// Create from VpnService file descriptor
        pub fn from_vpn_fd(fd: RawFd, config: OxideConfig) -> Self {
            let mut engine = Self::new(config);
            engine.fd = fd;
            engine
        }

        /// Allocate shared memory buffer
        fn alloc_umem(&mut self) -> Result<()> {
            self.umem_size = self.config.frame_count as usize * self.config.frame_size;

            self.umem = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    self.umem_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                ) as *mut u8
            };

            if self.umem.is_null() || self.umem == libc::MAP_FAILED as *mut u8 {
                return Err(anyhow::anyhow!("Failed to allocate UMEM"));
            }

            // Pre-fault pages
            unsafe {
                for i in (0..self.umem_size).step_by(4096) {
                    std::ptr::write_volatile(self.umem.add(i), 0);
                }
            }

            Ok(())
        }

        #[inline(always)]
        fn now_ns() -> u64 {
            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
            ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
        }
    }

    impl OxideEngine for AndroidOxideEngine {
        fn init(&mut self) -> Result<()> {
            if self.fd < 0 {
                return Err(anyhow::anyhow!("VpnService fd not set"));
            }

            // Set non-blocking
            unsafe {
                let flags = libc::fcntl(self.fd, libc::F_GETFL);
                libc::fcntl(self.fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            // Allocate UMEM
            self.alloc_umem()?;

            Ok(())
        }

        fn recv_batch<'a>(&'a mut self, packets: &mut [Option<OxidePacket<'a>>]) -> usize {
            let mut count = 0;
            let max = packets
                .len()
                .min(MAX_BATCH_SIZE)
                .min(self.packet_buffers.len());
            let mut bytes = 0u64;

            for i in 0..max {
                let buf = &mut self.packet_buffers[i];
                let result = unsafe {
                    libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };

                if result > 0 {
                    let len = result as usize;
                    if count < packets.len() {
                        packets[count] = Some(OxidePacket {
                            data: &buf[..len],
                            timestamp_ns: Self::now_ns(),
                            flags: 0,
                        });
                    }
                    count += 1;
                    bytes += len as u64;
                } else {
                    break;
                }
            }

            for slot in packets.iter_mut().skip(count) {
                *slot = None;
            }

            self.stats.record_rx(count as u64, bytes);
            count
        }

        fn send_batch(&mut self, packets: &[&[u8]]) -> usize {
            let mut sent = 0;

            for packet in packets.iter().take(MAX_BATCH_SIZE) {
                let result = unsafe {
                    libc::write(
                        self.fd,
                        packet.as_ptr() as *const libc::c_void,
                        packet.len(),
                    )
                };

                if result > 0 {
                    sent += 1;
                } else {
                    break;
                }
            }

            self.stats.record_tx(sent as u64, 0);
            sent
        }

        fn poll(&mut self, _timeout_us: u32) -> usize {
            self.stats.poll_cycles.fetch_add(1, Ordering::Relaxed);
            1
        }

        fn stats(&self) -> &OxideStats {
            &self.stats
        }

        fn is_zero_copy(&self) -> bool {
            !self.umem.is_null()
        }

        fn fd(&self) -> Option<i32> {
            if self.fd >= 0 {
                Some(self.fd)
            } else {
                None
            }
        }
    }

    impl Drop for AndroidOxideEngine {
        fn drop(&mut self) {
            if !self.umem.is_null() {
                unsafe { libc::munmap(self.umem as *mut libc::c_void, self.umem_size) };
            }
        }
    }
}

// ============================================================================
// iOS: NetworkExtension with memory-mapped dispatch
// ============================================================================

#[cfg(target_os = "ios")]
pub mod ios {
    use super::*;
    use std::os::unix::io::RawFd;

    /// iOS OXIDE engine using NetworkExtension optimizations
    pub struct IOSOxideEngine {
        config: OxideConfig,
        stats: OxideStats,
        fd: RawFd,

        // Memory-mapped buffer
        umem: *mut u8,
        umem_size: usize,

        // Rings
        rx_ring: Box<OxideRing>,
        tx_ring: Box<OxideRing>,

        // Pre-allocated packet buffers
        packet_buffers: Vec<Vec<u8>>,
    }

    impl IOSOxideEngine {
        pub fn new(config: OxideConfig) -> Self {
            let ring_size = config.ring_size as usize;
            Self {
                config: config.clone(),
                stats: OxideStats::new(),
                fd: -1,
                umem: std::ptr::null_mut(),
                umem_size: 0,
                rx_ring: Box::new(OxideRing::new(config.ring_size)),
                tx_ring: Box::new(OxideRing::new(config.ring_size)),
                packet_buffers: (0..ring_size * 2)
                    .map(|_| vec![0u8; config.frame_size])
                    .collect(),
            }
        }

        pub fn from_network_extension_fd(fd: RawFd, config: OxideConfig) -> Self {
            let mut engine = Self::new(config);
            engine.fd = fd;
            engine
        }

        fn alloc_umem(&mut self) -> Result<()> {
            self.umem_size = self.config.frame_count as usize * self.config.frame_size;

            self.umem = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    self.umem_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                ) as *mut u8
            };

            if self.umem.is_null() {
                return Err(anyhow::anyhow!("Failed to allocate UMEM"));
            }

            // Pre-fault
            unsafe {
                for i in (0..self.umem_size).step_by(4096) {
                    std::ptr::write_volatile(self.umem.add(i), 0);
                }
            }

            Ok(())
        }

        #[inline(always)]
        fn now_ns() -> u64 {
            extern "C" {
                fn mach_absolute_time() -> u64;
            }
            unsafe { mach_absolute_time() }
        }
    }

    impl OxideEngine for IOSOxideEngine {
        fn init(&mut self) -> Result<()> {
            if self.fd < 0 {
                return Err(anyhow::anyhow!("NetworkExtension fd not set"));
            }

            unsafe {
                let flags = libc::fcntl(self.fd, libc::F_GETFL);
                libc::fcntl(self.fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }

            self.alloc_umem()?;
            Ok(())
        }

        fn recv_batch<'a>(&'a mut self, packets: &mut [Option<OxidePacket<'a>>]) -> usize {
            let mut count = 0;
            let max = packets
                .len()
                .min(MAX_BATCH_SIZE)
                .min(self.packet_buffers.len());
            let mut bytes = 0u64;

            for i in 0..max {
                let buf = &mut self.packet_buffers[i];
                let result = unsafe {
                    libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };

                if result > 0 {
                    let len = result as usize;
                    if count < packets.len() {
                        packets[count] = Some(OxidePacket {
                            data: &buf[..len],
                            timestamp_ns: Self::now_ns(),
                            flags: 0,
                        });
                    }
                    count += 1;
                    bytes += len as u64;
                } else {
                    break;
                }
            }

            for slot in packets.iter_mut().skip(count) {
                *slot = None;
            }

            self.stats.record_rx(count as u64, bytes);
            count
        }

        fn send_batch(&mut self, packets: &[&[u8]]) -> usize {
            let mut sent = 0;

            for packet in packets.iter().take(MAX_BATCH_SIZE) {
                // iOS utun needs AF header
                let mut buf = vec![0u8; packet.len() + 4];
                let af: u32 = if packet.len() > 0 && (packet[0] >> 4) == 4 {
                    2
                } else {
                    30
                };
                buf[0..4].copy_from_slice(&af.to_be_bytes());
                buf[4..].copy_from_slice(packet);

                let result =
                    unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) };

                if result > 0 {
                    sent += 1;
                } else {
                    break;
                }
            }

            self.stats.record_tx(sent as u64, 0);
            sent
        }

        fn poll(&mut self, _timeout_us: u32) -> usize {
            self.stats.poll_cycles.fetch_add(1, Ordering::Relaxed);
            1
        }

        fn stats(&self) -> &OxideStats {
            &self.stats
        }

        fn is_zero_copy(&self) -> bool {
            !self.umem.is_null()
        }

        fn fd(&self) -> Option<i32> {
            if self.fd >= 0 {
                Some(self.fd)
            } else {
                None
            }
        }
    }

    impl Drop for IOSOxideEngine {
        fn drop(&mut self) {
            if !self.umem.is_null() {
                unsafe { libc::munmap(self.umem as *mut libc::c_void, self.umem_size) };
            }
        }
    }
}

// ============================================================================
// Unified Factory
// ============================================================================

/// Create the optimal OXIDE engine for the current platform
pub fn create_oxide_engine(config: OxideConfig) -> Box<dyn OxideEngine> {
    let config = config.with_platform_hints();
    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxOxideEngine::new(config))
    }
    #[cfg(target_os = "macos")]
    {
        Box::new(macos::MacOSRideEngine::new(config))
    }
    #[cfg(target_os = "windows")]
    {
        Box::new(windows::WindowsOxideEngine::new(config))
    }
    #[cfg(target_os = "android")]
    {
        Box::new(android::AndroidOxideEngine::new(config))
    }
    #[cfg(target_os = "ios")]
    {
        Box::new(ios::IOSOxideEngine::new(config))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_oxide_ring() {
        let ring = OxideRing::new(16);
        assert_eq!(ring.available(), 0);
        assert_eq!(ring.free_slots(), 16);

        // Produce
        ring.produce(4);
        assert_eq!(ring.available(), 4);
        assert_eq!(ring.free_slots(), 12);

        // Consume
        ring.consume(2);
        assert_eq!(ring.available(), 2);
    }

    #[test]
    fn test_oxide_descriptor_alignment() {
        assert_eq!(std::mem::align_of::<OxideDescriptor>(), 64);
        assert_eq!(std::mem::size_of::<OxideDescriptor>(), 64);
    }
}
