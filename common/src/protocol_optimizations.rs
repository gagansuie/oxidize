//! Protocol-Level Optimizations
//!
//! Medium Impact: Variable-length encoding, trusted networks, entropy detection

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

// =============================================================================
// Variable-Length Sequence Number Encoding (4→1-3 bytes for low sequences)
// =============================================================================

pub struct VarintCodec;

impl VarintCodec {
    /// Encode u32 as varint, returns bytes written
    #[inline]
    pub fn encode(value: u32, buf: &mut [u8]) -> usize {
        if value < 0x80 {
            buf[0] = value as u8;
            1
        } else if value < 0x4000 {
            buf[0] = ((value & 0x7f) | 0x80) as u8;
            buf[1] = (value >> 7) as u8;
            2
        } else if value < 0x200000 {
            buf[0] = ((value & 0x7f) | 0x80) as u8;
            buf[1] = (((value >> 7) & 0x7f) | 0x80) as u8;
            buf[2] = (value >> 14) as u8;
            3
        } else {
            buf[0] = ((value & 0x7f) | 0x80) as u8;
            buf[1] = (((value >> 7) & 0x7f) | 0x80) as u8;
            buf[2] = (((value >> 14) & 0x7f) | 0x80) as u8;
            buf[3] = (value >> 21) as u8;
            4
        }
    }

    /// Decode varint, returns (value, bytes_read)
    #[inline]
    pub fn decode(buf: &[u8]) -> Option<(u32, usize)> {
        if buf.is_empty() {
            return None;
        }
        let mut value: u32 = 0;
        let mut shift = 0;
        for (i, &byte) in buf.iter().enumerate() {
            if i >= 4 {
                return None;
            }
            value |= ((byte & 0x7f) as u32) << shift;
            if byte & 0x80 == 0 {
                return Some((value, i + 1));
            }
            shift += 7;
        }
        None
    }

    #[inline]
    pub fn encoded_size(value: u32) -> usize {
        if value < 0x80 {
            1
        } else if value < 0x4000 {
            2
        } else if value < 0x200000 {
            3
        } else {
            4
        }
    }
}

// =============================================================================
// Trusted Network Detection (Skip Encryption on Localhost/Private)
// =============================================================================

#[derive(Debug)]
pub struct TrustedNetworkDetector {
    trusted_prefixes: RwLock<Vec<TrustedNetwork>>,
    cache: RwLock<HashMap<IpAddr, bool>>,
    pub stats: TrustedNetworkStats,
}

#[derive(Debug, Clone)]
pub struct TrustedNetwork {
    pub prefix: IpAddr,
    pub prefix_len: u8,
    pub name: String,
}

#[derive(Debug, Default)]
pub struct TrustedNetworkStats {
    pub checks: AtomicU64,
    pub trusted_connections: AtomicU64,
    pub encryption_skipped: AtomicU64,
}

impl TrustedNetworkDetector {
    pub fn new() -> Self {
        let mut d = Self {
            trusted_prefixes: RwLock::new(Vec::new()),
            cache: RwLock::new(HashMap::new()),
            stats: TrustedNetworkStats::default(),
        };
        d.add_defaults();
        d
    }

    fn add_defaults(&mut self) {
        let defaults = vec![
            TrustedNetwork {
                prefix: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 0)),
                prefix_len: 8,
                name: "Localhost".into(),
            },
            TrustedNetwork {
                prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
                prefix_len: 8,
                name: "Private 10/8".into(),
            },
            TrustedNetwork {
                prefix: IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)),
                prefix_len: 12,
                name: "Private 172.16/12".into(),
            },
            TrustedNetwork {
                prefix: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
                prefix_len: 16,
                name: "Private 192.168/16".into(),
            },
            TrustedNetwork {
                prefix: IpAddr::V4(Ipv4Addr::new(169, 254, 0, 0)),
                prefix_len: 16,
                name: "Link-local".into(),
            },
        ];
        if let Ok(mut p) = self.trusted_prefixes.write() {
            *p = defaults;
        }
    }

    pub fn add_trusted(&self, network: TrustedNetwork) {
        if let Ok(mut p) = self.trusted_prefixes.write() {
            p.push(network);
        }
        if let Ok(mut c) = self.cache.write() {
            c.clear();
        }
    }

    pub fn is_trusted(&self, ip: IpAddr) -> bool {
        self.stats.checks.fetch_add(1, Ordering::Relaxed);

        if let Ok(c) = self.cache.read() {
            if let Some(&r) = c.get(&ip) {
                if r {
                    self.stats
                        .trusted_connections
                        .fetch_add(1, Ordering::Relaxed);
                }
                return r;
            }
        }

        let trusted = if let Ok(p) = self.trusted_prefixes.read() {
            p.iter().any(|n| self.ip_in_network(ip, n))
        } else {
            false
        };

        if let Ok(mut c) = self.cache.write() {
            c.insert(ip, trusted);
        }
        if trusted {
            self.stats
                .trusted_connections
                .fetch_add(1, Ordering::Relaxed);
        }
        trusted
    }

    fn ip_in_network(&self, ip: IpAddr, net: &TrustedNetwork) -> bool {
        match (ip, net.prefix) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = if net.prefix_len >= 32 {
                    !0u32
                } else {
                    !0u32 << (32 - net.prefix_len)
                };
                (u32::from(a) & mask) == (u32::from(b) & mask)
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mask = if net.prefix_len >= 128 {
                    !0u128
                } else {
                    !0u128 << (128 - net.prefix_len)
                };
                (u128::from(a) & mask) == (u128::from(b) & mask)
            }
            _ => false,
        }
    }

    pub fn should_skip_encryption(&self, src: IpAddr, dst: IpAddr) -> bool {
        let skip = self.is_trusted(src) && self.is_trusted(dst);
        if skip {
            self.stats
                .encryption_skipped
                .fetch_add(1, Ordering::Relaxed);
        }
        skip
    }
}

impl Default for TrustedNetworkDetector {
    fn default() -> Self {
        Self::new()
    }
}

// =============================================================================
// Dynamic Buffer Pool Sizing
// =============================================================================

#[derive(Debug)]
pub struct DynamicBufferPool {
    current_size: std::sync::atomic::AtomicUsize,
    min_size: usize,
    max_size: usize,
    high_watermark: f32,
    low_watermark: f32,
    in_use: std::sync::atomic::AtomicUsize,
    pub stats: BufferPoolStats,
}

#[derive(Debug, Default)]
pub struct BufferPoolStats {
    pub allocations: AtomicU64,
    pub deallocations: AtomicU64,
    pub expansions: AtomicU64,
    pub contractions: AtomicU64,
    pub peak_usage: std::sync::atomic::AtomicUsize,
    pub allocation_failures: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub enum ResizeAction {
    Expand(usize),
    Shrink(usize),
}

impl DynamicBufferPool {
    pub fn new(initial: usize, min: usize, max: usize) -> Self {
        Self {
            current_size: std::sync::atomic::AtomicUsize::new(initial),
            min_size: min,
            max_size: max,
            high_watermark: 0.8,
            low_watermark: 0.2,
            in_use: std::sync::atomic::AtomicUsize::new(0),
            stats: BufferPoolStats::default(),
        }
    }

    pub fn utilization(&self) -> f32 {
        let u = self.in_use.load(Ordering::Relaxed);
        let s = self.current_size.load(Ordering::Relaxed);
        if s == 0 {
            0.0
        } else {
            u as f32 / s as f32
        }
    }

    pub fn acquire(&self) -> bool {
        let u = self.in_use.fetch_add(1, Ordering::Relaxed);
        let s = self.current_size.load(Ordering::Relaxed);
        if u >= s {
            self.in_use.fetch_sub(1, Ordering::Relaxed);
            self.stats
                .allocation_failures
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.stats.allocations.fetch_add(1, Ordering::Relaxed);

        let current = u + 1;
        let mut peak = self.stats.peak_usage.load(Ordering::Relaxed);
        while current > peak {
            match self.stats.peak_usage.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
        true
    }

    pub fn release(&self) {
        self.in_use.fetch_sub(1, Ordering::Relaxed);
        self.stats.deallocations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn should_resize(&self) -> Option<ResizeAction> {
        let util = self.utilization();
        let cur = self.current_size.load(Ordering::Relaxed);
        if util > self.high_watermark && cur < self.max_size {
            Some(ResizeAction::Expand((cur * 2).min(self.max_size)))
        } else if util < self.low_watermark && cur > self.min_size {
            Some(ResizeAction::Shrink((cur / 2).max(self.min_size)))
        } else {
            None
        }
    }

    pub fn apply_resize(&self, action: ResizeAction) {
        match action {
            ResizeAction::Expand(new) => {
                self.current_size.store(new, Ordering::Relaxed);
                self.stats.expansions.fetch_add(1, Ordering::Relaxed);
            }
            ResizeAction::Shrink(new) => {
                if new >= self.in_use.load(Ordering::Relaxed) {
                    self.current_size.store(new, Ordering::Relaxed);
                    self.stats.contractions.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    pub fn size(&self) -> usize {
        self.current_size.load(Ordering::Relaxed)
    }
    pub fn in_use(&self) -> usize {
        self.in_use.load(Ordering::Relaxed)
    }
}

// =============================================================================
// NUMA-Aware Allocation
// =============================================================================

#[derive(Debug, Clone)]
pub struct NumaNode {
    pub id: u32,
    pub cpus: Vec<u32>,
    pub memory_mb: u64,
}

#[derive(Debug)]
pub struct NumaAllocator {
    nodes: Vec<NumaNode>,
    preferred_node: std::sync::atomic::AtomicU32,
    numa_available: bool,
    pub stats: NumaStats,
}

#[derive(Debug, Default)]
pub struct NumaStats {
    pub local_allocations: AtomicU64,
    pub remote_allocations: AtomicU64,
    pub node_switches: AtomicU64,
}

impl NumaAllocator {
    pub fn new() -> Self {
        let (nodes, available) = Self::detect_numa();
        Self {
            nodes,
            preferred_node: std::sync::atomic::AtomicU32::new(0),
            numa_available: available,
            stats: NumaStats::default(),
        }
    }

    #[cfg(target_os = "linux")]
    fn detect_numa() -> (Vec<NumaNode>, bool) {
        let path = std::path::Path::new("/sys/devices/system/node");
        if !path.exists() {
            return (
                vec![NumaNode {
                    id: 0,
                    cpus: vec![0],
                    memory_mb: 0,
                }],
                false,
            );
        }

        let mut nodes = Vec::new();
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let s = name.to_string_lossy();
                if let Some(suffix) = s.strip_prefix("node") {
                    if let Ok(id) = suffix.parse::<u32>() {
                        let cpus = std::fs::read_to_string(entry.path().join("cpulist"))
                            .ok()
                            .and_then(|s| Self::parse_cpulist(&s))
                            .unwrap_or_default();
                        nodes.push(NumaNode {
                            id,
                            cpus,
                            memory_mb: 0,
                        });
                    }
                }
            }
        }
        let available = nodes.len() > 1;
        if nodes.is_empty() {
            nodes.push(NumaNode {
                id: 0,
                cpus: vec![0],
                memory_mb: 0,
            });
        }
        (nodes, available)
    }

    #[cfg(not(target_os = "linux"))]
    fn detect_numa() -> (Vec<NumaNode>, bool) {
        (
            vec![NumaNode {
                id: 0,
                cpus: vec![0],
                memory_mb: 0,
            }],
            false,
        )
    }

    fn parse_cpulist(s: &str) -> Option<Vec<u32>> {
        let mut cpus = Vec::new();
        for part in s.trim().split(',') {
            if let Some((start, end)) = part.split_once('-') {
                let s: u32 = start.parse().ok()?;
                let e: u32 = end.parse().ok()?;
                cpus.extend(s..=e);
            } else {
                cpus.push(part.parse().ok()?);
            }
        }
        Some(cpus)
    }

    pub fn is_available(&self) -> bool {
        self.numa_available
    }
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn get_preferred_node(&self) -> u32 {
        self.preferred_node.load(Ordering::Relaxed)
    }

    pub fn set_preferred_node(&self, node: u32) {
        if (node as usize) < self.nodes.len() {
            self.preferred_node.store(node, Ordering::Relaxed);
            self.stats.node_switches.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn get_node_for_cpu(&self, cpu: u32) -> Option<u32> {
        self.nodes
            .iter()
            .find(|n| n.cpus.contains(&cpu))
            .map(|n| n.id)
    }
}

impl Default for NumaAllocator {
    fn default() -> Self {
        Self::new()
    }
}

/// Auto-select NUMA node based on current CPU affinity
/// Call this from worker threads to optimize memory locality
#[cfg(target_os = "linux")]
pub fn auto_set_numa_affinity(allocator: &NumaAllocator) {
    if !allocator.is_available() {
        return;
    }

    // Get current CPU
    let cpu = unsafe { libc::sched_getcpu() };
    if cpu >= 0 {
        if let Some(node) = allocator.get_node_for_cpu(cpu as u32) {
            allocator.set_preferred_node(node);
            allocator
                .stats
                .local_allocations
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn auto_set_numa_affinity(_allocator: &NumaAllocator) {
    // NUMA not available on non-Linux platforms
}
