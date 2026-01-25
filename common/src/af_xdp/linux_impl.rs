//! Linux AF_XDP implementation using raw libc syscalls

use std::ffi::CString;
use std::io::{self, Error, ErrorKind};
use std::mem;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tracing::{error, info};

use super::{XdpConfig, XdpStats};

// Linux kernel constants
const AF_XDP: i32 = 44;
const SOL_XDP: i32 = 283;
const XDP_MMAP_OFFSETS: i32 = 1;
const XDP_RX_RING: i32 = 2;
const XDP_TX_RING: i32 = 3;
const XDP_UMEM_REG: i32 = 4;
const XDP_UMEM_FILL_RING: i32 = 5;
const XDP_UMEM_COMPLETION_RING: i32 = 6;

const XDP_COPY: u16 = 1 << 1;
const XDP_ZEROCOPY: u16 = 1 << 2;
const XDP_USE_NEED_WAKEUP: u16 = 1 << 3;

const XDP_PGOFF_RX_RING: u64 = 0;
const XDP_PGOFF_TX_RING: u64 = 0x80000000;
const XDP_UMEM_PGOFF_FILL_RING: u64 = 0x100000000;
const XDP_UMEM_PGOFF_COMPLETION_RING: u64 = 0x180000000;

#[repr(C)]
#[derive(Default)]
struct XdpUmemReg {
    addr: u64,
    len: u64,
    chunk_size: u32,
    headroom: u32,
    flags: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct XdpRingOffset {
    producer: u64,
    consumer: u64,
    desc: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Default)]
struct XdpMmapOffsets {
    rx: XdpRingOffset,
    tx: XdpRingOffset,
    fr: XdpRingOffset,
    cr: XdpRingOffset,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct XdpDesc {
    addr: u64,
    len: u32,
    options: u32,
}

#[repr(C)]
struct SockaddrXdp {
    sxdp_family: u16,
    sxdp_flags: u16,
    sxdp_ifindex: u32,
    sxdp_queue_id: u32,
    sxdp_shared_umem_fd: u32,
}

#[allow(dead_code)]
struct Umem {
    area: *mut u8,
    size: usize,
    frame_size: u32,
    free_frames: Vec<u64>,
}

impl Umem {
    fn new(frame_count: u32, frame_size: u32) -> io::Result<Self> {
        let size = (frame_count as usize) * (frame_size as usize);

        let area = unsafe {
            libc::mmap(
                ptr::null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };

        if area == libc::MAP_FAILED {
            return Err(Error::last_os_error());
        }

        let free_frames: Vec<u64> = (0..frame_count)
            .map(|i| (i as u64) * (frame_size as u64))
            .collect();

        Ok(Umem {
            area: area as *mut u8,
            size,
            frame_size,
            free_frames,
        })
    }

    fn addr(&self) -> u64 {
        self.area as u64
    }
    fn alloc_frame(&mut self) -> Option<u64> {
        self.free_frames.pop()
    }
    fn free_frame(&mut self, addr: u64) {
        self.free_frames.push(addr);
    }

    fn get_data(&self, addr: u64, len: usize) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.area.add(addr as usize), len) }
    }

    fn get_data_mut(&mut self, addr: u64, len: usize) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.area.add(addr as usize), len) }
    }
}

impl Drop for Umem {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.area as *mut libc::c_void, self.size);
        }
    }
}

struct XdpRing {
    producer: *mut AtomicU32,
    consumer: *mut AtomicU32,
    ring: *mut u8,
    mask: u32,
}

impl XdpRing {
    unsafe fn new(map_addr: *mut u8, offsets: &XdpRingOffset, size: u32) -> Self {
        XdpRing {
            producer: map_addr.add(offsets.producer as usize) as *mut AtomicU32,
            consumer: map_addr.add(offsets.consumer as usize) as *mut AtomicU32,
            ring: map_addr.add(offsets.desc as usize),
            mask: size - 1,
        }
    }

    fn prod_peek(&self) -> u32 {
        unsafe { (*self.producer).load(Ordering::Acquire) }
    }
    fn cons_peek(&self) -> u32 {
        unsafe { (*self.consumer).load(Ordering::Acquire) }
    }
    fn prod_advance(&self, n: u32) {
        unsafe {
            (*self.producer).fetch_add(n, Ordering::Release);
        }
    }
    fn cons_advance(&self, n: u32) {
        unsafe {
            (*self.consumer).fetch_add(n, Ordering::Release);
        }
    }
}

/// Packet received from AF_XDP
#[derive(Debug)]
pub struct XdpPacket {
    pub data: Vec<u8>,
    pub frame_addr: u64,
    pub timestamp: Instant,
}

/// AF_XDP Socket for zero-copy packet I/O
pub struct XdpSocket {
    fd: RawFd,
    config: XdpConfig,
    umem: Umem,
    rx_ring: XdpRing,
    tx_ring: XdpRing,
    fill_ring: XdpRing,
    comp_ring: XdpRing,
    pub stats: Arc<XdpStats>,
    start_time: Instant,
}

impl XdpSocket {
    /// Create and initialize AF_XDP socket
    pub fn new(config: XdpConfig) -> io::Result<Self> {
        info!("Creating AF_XDP socket on {}", config.interface);

        let ifindex = Self::get_ifindex(&config.interface)?;
        let fd = unsafe { libc::socket(AF_XDP, libc::SOCK_RAW, 0) };
        if fd < 0 {
            return Err(Error::last_os_error());
        }

        let umem = Umem::new(config.frame_count, config.frame_size)?;
        info!(
            "UMEM: {} frames x {} bytes",
            config.frame_count, config.frame_size
        );

        // Register UMEM
        let umem_reg = XdpUmemReg {
            addr: umem.addr(),
            len: umem.size as u64,
            chunk_size: config.frame_size,
            headroom: config.headroom,
            flags: 0,
        };

        if unsafe {
            libc::setsockopt(
                fd,
                SOL_XDP,
                XDP_UMEM_REG,
                &umem_reg as *const _ as *const libc::c_void,
                mem::size_of::<XdpUmemReg>() as u32,
            )
        } < 0
        {
            unsafe {
                libc::close(fd);
            }
            return Err(Error::last_os_error());
        }

        // Set ring sizes
        for (opt, size) in [
            (XDP_UMEM_FILL_RING, config.fill_ring_size),
            (XDP_UMEM_COMPLETION_RING, config.comp_ring_size),
            (XDP_RX_RING, config.rx_ring_size),
            (XDP_TX_RING, config.tx_ring_size),
        ] {
            if unsafe {
                libc::setsockopt(
                    fd,
                    SOL_XDP,
                    opt,
                    &size as *const _ as *const libc::c_void,
                    mem::size_of::<u32>() as u32,
                )
            } < 0
            {
                unsafe {
                    libc::close(fd);
                }
                return Err(Error::last_os_error());
            }
        }

        // Get mmap offsets
        let mut offsets = XdpMmapOffsets::default();
        let mut optlen = mem::size_of::<XdpMmapOffsets>() as u32;
        if unsafe {
            libc::getsockopt(
                fd,
                SOL_XDP,
                XDP_MMAP_OFFSETS,
                &mut offsets as *mut _ as *mut libc::c_void,
                &mut optlen,
            )
        } < 0
        {
            unsafe {
                libc::close(fd);
            }
            return Err(Error::last_os_error());
        }

        info!("Mapping rings...");
        // Map rings
        let fill_ring = Self::map_ring(
            fd,
            XDP_UMEM_PGOFF_FILL_RING,
            &offsets.fr,
            config.fill_ring_size,
        )?;
        let comp_ring = Self::map_ring(
            fd,
            XDP_UMEM_PGOFF_COMPLETION_RING,
            &offsets.cr,
            config.comp_ring_size,
        )?;
        let rx_ring = Self::map_ring(fd, XDP_PGOFF_RX_RING, &offsets.rx, config.rx_ring_size)?;
        let tx_ring = Self::map_ring(fd, XDP_PGOFF_TX_RING, &offsets.tx, config.tx_ring_size)?;

        info!(
            "Binding socket to interface index {} queue {}...",
            ifindex, config.queue_id
        );
        // Bind socket
        let sxdp = SockaddrXdp {
            sxdp_family: AF_XDP as u16,
            sxdp_flags: if config.zero_copy {
                XDP_ZEROCOPY
            } else {
                XDP_COPY
            } | XDP_USE_NEED_WAKEUP,
            sxdp_ifindex: ifindex,
            sxdp_queue_id: config.queue_id,
            sxdp_shared_umem_fd: 0,
        };

        let mut bound = false;
        if unsafe {
            libc::bind(
                fd,
                &sxdp as *const _ as *const libc::sockaddr,
                mem::size_of::<SockaddrXdp>() as u32,
            )
        } == 0
        {
            info!("Bound in zero-copy mode");
            bound = true;
        }

        if !bound {
            let err = Error::last_os_error();
            info!("Zero-copy bind failed: {}, trying copy mode...", err);
            let sxdp_copy = SockaddrXdp {
                sxdp_flags: XDP_COPY | XDP_USE_NEED_WAKEUP,
                ..sxdp
            };
            if unsafe {
                libc::bind(
                    fd,
                    &sxdp_copy as *const _ as *const libc::sockaddr,
                    mem::size_of::<SockaddrXdp>() as u32,
                )
            } < 0
            {
                let copy_err = Error::last_os_error();
                error!("Copy mode bind also failed: {}", copy_err);
                unsafe {
                    libc::close(fd);
                }
                return Err(copy_err);
            }
            info!("Bound in copy mode");
        }

        if config.busy_poll {
            let budget = config.busy_poll_budget as i32;
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_BUSY_POLL_BUDGET,
                    &budget as *const _ as *const libc::c_void,
                    mem::size_of::<i32>() as u32,
                );
            }
        }

        info!(
            "AF_XDP socket ready on {}:{}",
            config.interface, config.queue_id
        );

        Ok(XdpSocket {
            fd,
            config,
            umem,
            rx_ring,
            tx_ring,
            fill_ring,
            comp_ring,
            stats: Arc::new(XdpStats::new()),
            start_time: Instant::now(),
        })
    }

    fn map_ring(fd: RawFd, pgoff: u64, offsets: &XdpRingOffset, size: u32) -> io::Result<XdpRing> {
        let map_size = offsets.desc as usize + (size as usize) * mem::size_of::<XdpDesc>();
        info!("  mmap: size={} pgoff={:#x}", map_size, pgoff);
        let map_addr = unsafe {
            libc::mmap(
                ptr::null_mut(),
                map_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_POPULATE,
                fd,
                pgoff as i64,
            )
        };
        if map_addr == libc::MAP_FAILED {
            let err = Error::last_os_error();
            error!("  mmap failed: {}", err);
            return Err(err);
        }
        Ok(unsafe { XdpRing::new(map_addr as *mut u8, offsets, size) })
    }

    fn get_ifindex(interface: &str) -> io::Result<u32> {
        let ifname = CString::new(interface)
            .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid interface"))?;
        let idx = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
        if idx == 0 {
            Err(Error::last_os_error())
        } else {
            Ok(idx)
        }
    }

    /// Check if AF_XDP is supported
    pub fn is_supported() -> bool {
        if let Ok(v) = std::fs::read_to_string("/proc/version") {
            if let Some(ver) = v.split_whitespace().nth(2) {
                let parts: Vec<&str> = ver.split('.').collect();
                if parts.len() >= 2 {
                    if let (Ok(maj), Ok(min)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                        return maj > 5 || (maj == 5 && min >= 4);
                    }
                }
            }
        }
        false
    }

    /// Populate fill ring
    pub fn populate_fill_ring(&mut self) -> u32 {
        let prod = self.fill_ring.prod_peek();
        let cons = self.fill_ring.cons_peek();
        let free = self.config.fill_ring_size - (prod - cons);
        let mut filled = 0u32;

        for _ in 0..free {
            if let Some(addr) = self.umem.alloc_frame() {
                let idx = (prod + filled) & self.fill_ring.mask;
                unsafe {
                    let ptr = self.fill_ring.ring.add((idx as usize) * 8) as *mut u64;
                    *ptr = addr;
                }
                filled += 1;
            } else {
                break;
            }
        }
        if filled > 0 {
            self.fill_ring.prod_advance(filled);
        }
        filled
    }

    /// Receive packets
    pub fn recv(&mut self, batch_size: usize) -> Vec<XdpPacket> {
        self.populate_fill_ring();

        let prod = self.rx_ring.prod_peek();
        let cons = self.rx_ring.cons_peek();
        let avail = prod - cons;
        if avail == 0 {
            return Vec::new();
        }

        let to_read = std::cmp::min(avail as usize, batch_size);
        let mut packets = Vec::with_capacity(to_read);
        let ts = Instant::now();

        for i in 0..to_read {
            let idx = (cons + i as u32) & self.rx_ring.mask;
            let desc: XdpDesc = unsafe {
                *(self
                    .rx_ring
                    .ring
                    .add((idx as usize) * mem::size_of::<XdpDesc>())
                    as *const XdpDesc)
            };
            packets.push(XdpPacket {
                data: self.umem.get_data(desc.addr, desc.len as usize).to_vec(),
                frame_addr: desc.addr,
                timestamp: ts,
            });
            self.stats
                .rx_bytes
                .fetch_add(desc.len as u64, Ordering::Relaxed);
        }

        self.rx_ring.cons_advance(to_read as u32);
        self.stats
            .rx_packets
            .fetch_add(to_read as u64, Ordering::Relaxed);
        self.stats.rx_batches.fetch_add(1, Ordering::Relaxed);
        packets
    }

    /// Return frames after processing
    pub fn return_frames(&mut self, frames: &[u64]) {
        for &addr in frames {
            self.umem.free_frame(addr);
        }
    }

    /// Transmit packets
    pub fn send(&mut self, packets: &[&[u8]]) -> usize {
        let prod = self.tx_ring.prod_peek();
        let cons = self.tx_ring.cons_peek();
        let free = self.config.tx_ring_size - (prod - cons);
        let to_send = std::cmp::min(packets.len(), free as usize);
        let mut sent = 0;

        for pkt in packets.iter().take(to_send) {
            if let Some(addr) = self.umem.alloc_frame() {
                let hdr = self.config.headroom as usize;
                self.umem
                    .get_data_mut(addr + hdr as u64, pkt.len())
                    .copy_from_slice(pkt);

                let idx = (prod + sent as u32) & self.tx_ring.mask;
                unsafe {
                    let ptr = self
                        .tx_ring
                        .ring
                        .add((idx as usize) * mem::size_of::<XdpDesc>())
                        as *mut XdpDesc;
                    *ptr = XdpDesc {
                        addr: addr + hdr as u64,
                        len: pkt.len() as u32,
                        options: 0,
                    };
                }
                self.stats
                    .tx_bytes
                    .fetch_add(pkt.len() as u64, Ordering::Relaxed);
                sent += 1;
            } else {
                break;
            }
        }

        if sent > 0 {
            self.tx_ring.prod_advance(sent as u32);
            unsafe {
                libc::sendto(self.fd, ptr::null(), 0, libc::MSG_DONTWAIT, ptr::null(), 0);
            }
            self.stats
                .tx_packets
                .fetch_add(sent as u64, Ordering::Relaxed);
            self.stats.tx_batches.fetch_add(1, Ordering::Relaxed);
        }

        self.process_completions();
        sent
    }

    fn process_completions(&mut self) {
        let prod = self.comp_ring.prod_peek();
        let cons = self.comp_ring.cons_peek();
        let avail = prod - cons;

        for i in 0..avail {
            let idx = (cons + i) & self.comp_ring.mask;
            let addr: u64 = unsafe { *(self.comp_ring.ring.add((idx as usize) * 8) as *const u64) };
            self.umem.free_frame(addr - self.config.headroom as u64);
        }
        if avail > 0 {
            self.comp_ring.cons_advance(avail);
        }
    }

    /// Poll for events
    pub fn poll(&self, timeout_ms: i32) -> bool {
        let mut pfd = libc::pollfd {
            fd: self.fd,
            events: libc::POLLIN | libc::POLLOUT,
            revents: 0,
        };
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) > 0 }
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
    pub fn stats(&self) -> &Arc<XdpStats> {
        &self.stats
    }
    pub fn elapsed(&self) -> std::time::Duration {
        self.start_time.elapsed()
    }
}

impl Drop for XdpSocket {
    fn drop(&mut self) {
        info!("Closing AF_XDP socket");
        unsafe {
            libc::close(self.fd);
        }
    }
}

impl AsRawFd for XdpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}
