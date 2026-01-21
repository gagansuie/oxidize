//! DPDK Mbuf (Memory Buffer) management
//!
//! High-performance packet buffer pool using DPDK mbufs allocated from hugepages.

#[cfg(feature = "dpdk")]
use std::ptr::NonNull;
use std::sync::Arc;

use tracing::info;

#[cfg(feature = "dpdk")]
use super::dpdk_bindings::*;

/// Mbuf pool for packet allocation
pub struct MbufPool {
    #[cfg(feature = "dpdk")]
    pool: NonNull<rte_mempool>,
    #[cfg(not(feature = "dpdk"))]
    _pool: std::marker::PhantomData<()>,
    /// Pool name
    pub name: String,
    /// Number of mbufs
    pub size: u32,
    /// Per-core cache size
    pub cache_size: u32,
    /// Data room size per mbuf
    pub data_room_size: u16,
}

unsafe impl Send for MbufPool {}
unsafe impl Sync for MbufPool {}

impl MbufPool {
    /// Default data room size (includes headroom)
    pub const DEFAULT_DATA_ROOM: u16 = 2048 + 128; // RTE_MBUF_DEFAULT_DATAROOM

    /// Create a new mbuf pool
    pub fn new(
        name: &str,
        size: u32,
        cache_size: u32,
        socket_id: i32,
    ) -> Result<Arc<Self>, MbufError> {
        Self::with_data_room(name, size, cache_size, Self::DEFAULT_DATA_ROOM, socket_id)
    }

    /// Create mbuf pool with custom data room size
    #[allow(unused_variables)]
    pub fn with_data_room(
        name: &str,
        size: u32,
        cache_size: u32,
        data_room_size: u16,
        socket_id: i32,
    ) -> Result<Arc<Self>, MbufError> {
        info!(
            "Creating mbuf pool '{}': {} mbufs, cache={}, data_room={}",
            name, size, cache_size, data_room_size
        );

        #[cfg(feature = "dpdk")]
        {
            use std::ffi::CString;
            let c_name = CString::new(name).map_err(|_| MbufError::InvalidName)?;

            let pool = unsafe {
                rte_pktmbuf_pool_create(
                    c_name.as_ptr(),
                    size,
                    cache_size,
                    0, // priv_size
                    data_room_size,
                    socket_id,
                )
            };

            if pool.is_null() {
                return Err(MbufError::AllocationFailed);
            }

            Ok(Arc::new(Self {
                pool: NonNull::new(pool).unwrap(),
                name: name.to_string(),
                size,
                cache_size,
                data_room_size,
            }))
        }

        #[cfg(not(feature = "dpdk"))]
        {
            Ok(Arc::new(Self {
                _pool: std::marker::PhantomData,
                name: name.to_string(),
                size,
                cache_size,
                data_room_size,
            }))
        }
    }

    /// Allocate a single mbuf
    #[cfg(feature = "dpdk")]
    pub fn alloc(&self) -> Option<Mbuf> {
        let mbuf = unsafe { rte_pktmbuf_alloc(self.pool.as_ptr()) };
        if mbuf.is_null() {
            None
        } else {
            Some(Mbuf {
                raw: NonNull::new(mbuf).unwrap(),
            })
        }
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn alloc(&self) -> Option<Mbuf> {
        Some(Mbuf::simulated())
    }

    /// Allocate multiple mbufs in bulk
    #[cfg(feature = "dpdk")]
    pub fn alloc_bulk(&self, count: usize) -> Result<Vec<Mbuf>, MbufError> {
        let mut ptrs: Vec<*mut rte_mbuf> = vec![std::ptr::null_mut(); count];

        let ret =
            unsafe { rte_pktmbuf_alloc_bulk(self.pool.as_ptr(), ptrs.as_mut_ptr(), count as u32) };

        if ret != 0 {
            return Err(MbufError::AllocationFailed);
        }

        Ok(ptrs
            .into_iter()
            .filter_map(|p| NonNull::new(p).map(|raw| Mbuf { raw }))
            .collect())
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn alloc_bulk(&self, count: usize) -> Result<Vec<Mbuf>, MbufError> {
        Ok((0..count).map(|_| Mbuf::simulated()).collect())
    }

    /// Get raw pointer to the mempool (for DPDK operations)
    #[cfg(feature = "dpdk")]
    pub fn as_ptr(&self) -> *mut rte_mempool {
        self.pool.as_ptr()
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn as_ptr(&self) -> *mut () {
        std::ptr::null_mut()
    }
}

/// Individual packet buffer (mbuf wrapper)
pub struct Mbuf {
    #[cfg(feature = "dpdk")]
    raw: NonNull<rte_mbuf>,
    #[cfg(not(feature = "dpdk"))]
    data: Vec<u8>,
}

unsafe impl Send for Mbuf {}

impl Mbuf {
    /// Create a simulated mbuf for non-DPDK builds
    #[cfg(not(feature = "dpdk"))]
    fn simulated() -> Self {
        Self {
            data: vec![0u8; 2048],
        }
    }

    /// Create an Mbuf from a raw pointer (for internal use)
    #[cfg(feature = "dpdk")]
    pub(crate) fn from_raw(ptr: NonNull<rte_mbuf>) -> Self {
        Self { raw: ptr }
    }

    /// Get raw pointer to the underlying rte_mbuf
    #[cfg(feature = "dpdk")]
    pub fn as_ptr(&self) -> *mut rte_mbuf {
        self.raw.as_ptr()
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn as_ptr(&self) -> *mut () {
        std::ptr::null_mut()
    }

    /// Get raw pointer to mbuf data
    #[cfg(feature = "dpdk")]
    pub fn data_ptr(&self) -> *mut u8 {
        unsafe { rte_pktmbuf_mtod(self.raw.as_ptr()) as *mut u8 }
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn data_ptr(&self) -> *mut u8 {
        self.data.as_ptr() as *mut u8
    }

    /// Get data as slice
    #[cfg(feature = "dpdk")]
    pub fn data(&self) -> &[u8] {
        let len = self.data_len();
        unsafe { std::slice::from_raw_parts(self.data_ptr(), len as usize) }
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Get mutable data slice
    #[cfg(feature = "dpdk")]
    pub fn data_mut(&mut self) -> &mut [u8] {
        let len = self.data_len();
        unsafe { std::slice::from_raw_parts_mut(self.data_ptr(), len as usize) }
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get data length
    #[cfg(feature = "dpdk")]
    pub fn data_len(&self) -> u16 {
        unsafe { rte_pktmbuf_data_len(self.raw.as_ptr()) }
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn data_len(&self) -> u16 {
        self.data.len() as u16
    }

    /// Get packet length (including chained mbufs)
    #[cfg(feature = "dpdk")]
    pub fn pkt_len(&self) -> u32 {
        unsafe { rte_pktmbuf_pkt_len(self.raw.as_ptr()) }
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn pkt_len(&self) -> u32 {
        self.data.len() as u32
    }

    /// Append data to mbuf
    #[cfg(feature = "dpdk")]
    pub fn append(&mut self, len: u16) -> Option<*mut u8> {
        let ptr = unsafe { rte_pktmbuf_append(self.raw.as_ptr(), len) };
        if ptr.is_null() {
            None
        } else {
            Some(ptr as *mut u8)
        }
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn append(&mut self, len: u16) -> Option<*mut u8> {
        let old_len = self.data.len();
        self.data.resize(old_len + len as usize, 0);
        Some(self.data[old_len..].as_mut_ptr())
    }

    /// Prepend data to mbuf
    #[cfg(feature = "dpdk")]
    pub fn prepend(&mut self, len: u16) -> Option<*mut u8> {
        let ptr = unsafe { rte_pktmbuf_prepend(self.raw.as_ptr(), len) };
        if ptr.is_null() {
            None
        } else {
            Some(ptr as *mut u8)
        }
    }

    /// Adjust data offset (remove from front)
    #[cfg(feature = "dpdk")]
    pub fn adj(&mut self, len: u16) -> Option<*mut u8> {
        let ptr = unsafe { rte_pktmbuf_adj(self.raw.as_ptr(), len) };
        if ptr.is_null() {
            None
        } else {
            Some(ptr as *mut u8)
        }
    }

    /// Trim data from end
    #[cfg(feature = "dpdk")]
    pub fn trim(&mut self, len: u16) -> bool {
        unsafe { rte_pktmbuf_trim(self.raw.as_ptr(), len) == 0 }
    }

    #[cfg(not(feature = "dpdk"))]
    pub fn trim(&mut self, len: u16) -> bool {
        if len as usize <= self.data.len() {
            self.data.truncate(self.data.len() - len as usize);
            true
        } else {
            false
        }
    }

    /// Get raw mbuf pointer (for DPDK functions)
    #[cfg(feature = "dpdk")]
    pub fn raw_ptr(&self) -> *mut rte_mbuf {
        self.raw.as_ptr()
    }

    /// Parse Ethernet header
    pub fn parse_eth_header(&self) -> Option<EthHeader> {
        let data = self.data();
        if data.len() < 14 {
            return None;
        }

        Some(EthHeader {
            dst_mac: [data[0], data[1], data[2], data[3], data[4], data[5]],
            src_mac: [data[6], data[7], data[8], data[9], data[10], data[11]],
            ether_type: u16::from_be_bytes([data[12], data[13]]),
        })
    }
}

#[cfg(feature = "dpdk")]
impl Drop for Mbuf {
    fn drop(&mut self) {
        unsafe { rte_pktmbuf_free(self.raw.as_ptr()) }
    }
}

/// Parsed Ethernet header
#[derive(Debug, Clone, Copy)]
pub struct EthHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

/// Mbuf allocation errors
#[derive(Debug)]
pub enum MbufError {
    InvalidName,
    AllocationFailed,
    PoolExhausted,
}

impl std::fmt::Display for MbufError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MbufError::InvalidName => write!(f, "Invalid pool name"),
            MbufError::AllocationFailed => write!(f, "Mbuf allocation failed"),
            MbufError::PoolExhausted => write!(f, "Mbuf pool exhausted"),
        }
    }
}

impl std::error::Error for MbufError {}

/// Batch of mbufs for bulk processing
pub struct MbufBatch {
    mbufs: Vec<Mbuf>,
    capacity: usize,
}

impl MbufBatch {
    pub fn new(capacity: usize) -> Self {
        Self {
            mbufs: Vec::with_capacity(capacity),
            capacity,
        }
    }

    pub fn push(&mut self, mbuf: Mbuf) -> bool {
        if self.mbufs.len() < self.capacity {
            self.mbufs.push(mbuf);
            true
        } else {
            false
        }
    }

    pub fn len(&self) -> usize {
        self.mbufs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mbufs.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.mbufs.len() >= self.capacity
    }

    pub fn clear(&mut self) {
        self.mbufs.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = &Mbuf> {
        self.mbufs.iter()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Mbuf> {
        self.mbufs.iter_mut()
    }

    pub fn drain(&mut self) -> impl Iterator<Item = Mbuf> + '_ {
        self.mbufs.drain(..)
    }
}
