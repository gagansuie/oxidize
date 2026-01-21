//! Raw DPDK FFI bindings
//!
//! Low-level bindings to DPDK C library functions.
//! These are used by the higher-level safe Rust wrappers.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::os::raw::{c_char, c_int, c_uint, c_void};

/// DPDK port ID type
pub type PortId = u16;
/// DPDK queue ID type  
pub type QueueId = u16;
/// DPDK lcore ID type
pub type LcoreId = u32;

/// RTE mbuf structure - simplified for our use case
/// Full DPDK rte_mbuf is much larger, but we only need these fields
#[repr(C)]
pub struct rte_mbuf {
    pub buf_addr: *mut c_void,
    pub buf_iova: u64,
    pub rearm_data: [u8; 8],
    pub data_off: u16,
    pub refcnt: u16,
    pub nb_segs: u16,
    pub port: u16,
    pub ol_flags: u64,
    pub packet_type: u32,
    pub pkt_len: u32,
    pub data_len: u16,
    pub vlan_tci: u16,
    pub rss_hash: u32,
    pub vlan_tci_outer: u16,
    pub buf_len: u16,
    pub timestamp: u64,
    pub userdata: u64,
    pub pool: *mut rte_mempool,
    pub next: *mut rte_mbuf,
    pub tx_offload: u64,
    pub priv_size: u16,
    pub timesync: u16,
    pub seqn: u32,
    pub shinfo: *mut c_void,
    _padding: [u8; 64], // Padding for cache line alignment
}

/// RTE mempool structure (opaque pointer)
#[repr(C)]
pub struct rte_mempool {
    _private: [u8; 0],
}

/// Ethernet address
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct rte_ether_addr {
    pub addr_bytes: [u8; 6],
}

/// Ethernet header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct rte_ether_hdr {
    pub dst_addr: rte_ether_addr,
    pub src_addr: rte_ether_addr,
    pub ether_type: u16,
}

/// IPv4 header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct rte_ipv4_hdr {
    pub version_ihl: u8,
    pub type_of_service: u8,
    pub total_length: u16,
    pub packet_id: u16,
    pub fragment_offset: u16,
    pub time_to_live: u8,
    pub next_proto_id: u8,
    pub hdr_checksum: u16,
    pub src_addr: u32,
    pub dst_addr: u32,
}

/// IPv6 header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct rte_ipv6_hdr {
    pub vtc_flow: u32,
    pub payload_len: u16,
    pub proto: u8,
    pub hop_limits: u8,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
}

/// UDP header
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct rte_udp_hdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub dgram_len: u16,
    pub dgram_cksum: u16,
}

/// Ethernet device configuration
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_eth_conf {
    pub link_speeds: u32,
    pub rxmode: rte_eth_rxmode,
    pub txmode: rte_eth_txmode,
    pub lpbk_mode: u32,
    pub rx_adv_conf: rte_eth_rx_adv_conf,
    pub tx_adv_conf: rte_eth_tx_adv_conf,
    pub dcb_capability_en: u32,
    pub fdir_conf: rte_fdir_conf,
    pub intr_conf: rte_intr_conf,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_eth_rxmode {
    pub mq_mode: u32,
    pub mtu: u32,
    pub max_lro_pkt_size: u32,
    pub offloads: u64,
    pub reserved_64s: [u64; 2],
    pub reserved_ptrs: [*mut c_void; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_eth_txmode {
    pub mq_mode: u32,
    pub offloads: u64,
    pub pvid: u16,
    pub hw_vlan_reject_tagged: u8,
    pub hw_vlan_reject_untagged: u8,
    pub hw_vlan_insert_pvid: u8,
    pub reserved_64s: [u64; 2],
    pub reserved_ptrs: [*mut c_void; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_eth_rx_adv_conf {
    pub rss_conf: rte_eth_rss_conf,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_eth_tx_adv_conf {
    _placeholder: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_eth_rss_conf {
    pub rss_key: *mut u8,
    pub rss_key_len: u8,
    pub rss_hf: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_fdir_conf {
    pub mode: u32,
    pub pballoc: u32,
    pub status: u32,
    pub drop_queue: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_intr_conf {
    pub lsc: u16,
    pub rxq: u16,
    pub rmv: u16,
}

/// RX queue configuration
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_eth_rxconf {
    pub rx_thresh: rte_eth_thresh,
    pub rx_free_thresh: u16,
    pub rx_drop_en: u8,
    pub rx_deferred_start: u8,
    pub rx_nseg: u16,
    pub share_group: u16,
    pub share_qid: u16,
    pub offloads: u64,
    pub rx_seg: *mut c_void,
    pub reserved_64s: [u64; 2],
    pub reserved_ptrs: [*mut c_void; 2],
}

/// TX queue configuration
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_eth_txconf {
    pub tx_thresh: rte_eth_thresh,
    pub tx_rs_thresh: u16,
    pub tx_free_thresh: u16,
    pub tx_deferred_start: u8,
    pub offloads: u64,
    pub reserved_64s: [u64; 2],
    pub reserved_ptrs: [*mut c_void; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct rte_eth_thresh {
    pub pthresh: u8,
    pub hthresh: u8,
    pub wthresh: u8,
}

/// Device info
#[repr(C)]
pub struct rte_eth_dev_info {
    pub device: *mut c_void,
    pub driver_name: *const c_char,
    pub if_index: c_uint,
    pub min_mtu: u16,
    pub max_mtu: u16,
    pub dev_flags: *const u32,
    pub min_rx_bufsize: u32,
    pub max_rx_pktlen: u32,
    pub max_lro_pkt_size: u32,
    pub max_rx_queues: u16,
    pub max_tx_queues: u16,
    pub max_mac_addrs: u32,
    pub max_hash_mac_addrs: u32,
    pub max_vfs: u16,
    pub max_vmdq_pools: u16,
    pub rx_seg_capa: [u8; 32],
    pub rx_offload_capa: u64,
    pub tx_offload_capa: u64,
    pub rx_queue_offload_capa: u64,
    pub tx_queue_offload_capa: u64,
    pub reta_size: u16,
    pub hash_key_size: u8,
    pub flow_type_rss_offloads: u64,
    pub default_rxconf: rte_eth_rxconf,
    pub default_txconf: rte_eth_txconf,
    pub vmdq_queue_base: u16,
    pub vmdq_queue_num: u16,
    pub vmdq_pool_base: u16,
    pub rx_desc_lim: [u8; 24],
    pub tx_desc_lim: [u8; 24],
    pub speed_capa: u32,
    pub nb_rx_queues: u16,
    pub nb_tx_queues: u16,
    pub dev_capa: u64,
    pub switch_info: [u8; 32],
    pub reserved_64s: [u64; 2],
    pub reserved_ptrs: [*mut c_void; 2],
}

// Protocol constants
pub const RTE_ETHER_TYPE_IPV4: u16 = 0x0800;
pub const RTE_ETHER_TYPE_IPV6: u16 = 0x86DD;
pub const IPPROTO_UDP: u8 = 17;

// Offload flags
pub const RTE_ETH_TX_OFFLOAD_IPV4_CKSUM: u64 = 1 << 1;
pub const RTE_ETH_TX_OFFLOAD_UDP_CKSUM: u64 = 1 << 2;
pub const RTE_ETH_TX_OFFLOAD_MULTI_SEGS: u64 = 1 << 15;
pub const RTE_ETH_RX_OFFLOAD_CHECKSUM: u64 = 1 << 0;
pub const RTE_ETH_RX_OFFLOAD_RSS_HASH: u64 = 1 << 19;

// RSS hash types
pub const RTE_ETH_RSS_IP: u64 = 1 << 0;
pub const RTE_ETH_RSS_UDP: u64 = 1 << 5;
pub const RTE_ETH_RSS_NONFRAG_IPV4_UDP: u64 = 1 << 8;
pub const RTE_ETH_RSS_NONFRAG_IPV6_UDP: u64 = 1 << 12;

// Mbuf flags
pub const RTE_MBUF_F_TX_IP_CKSUM: u64 = 1 << 54;
pub const RTE_MBUF_F_TX_UDP_CKSUM: u64 = 2 << 52;
pub const RTE_MBUF_F_TX_IPV4: u64 = 1 << 55;
pub const RTE_MBUF_F_TX_IPV6: u64 = 1 << 56;

// Link speeds
pub const RTE_ETH_LINK_SPEED_10G: u32 = 1 << 8;
pub const RTE_ETH_LINK_SPEED_25G: u32 = 1 << 9;
pub const RTE_ETH_LINK_SPEED_40G: u32 = 1 << 10;
pub const RTE_ETH_LINK_SPEED_100G: u32 = 1 << 12;

// DPDK EAL functions (would be linked from libdpdk)
#[cfg(feature = "dpdk")]
extern "C" {
    pub fn rte_eal_init(argc: c_int, argv: *mut *mut c_char) -> c_int;
    pub fn rte_eal_cleanup() -> c_int;
    pub fn rte_lcore_id() -> LcoreId;
    pub fn rte_lcore_count() -> c_uint;
    pub fn rte_get_main_lcore() -> LcoreId;
    pub fn rte_socket_id() -> c_int;

    pub fn rte_pktmbuf_pool_create(
        name: *const c_char,
        n: c_uint,
        cache_size: c_uint,
        priv_size: u16,
        data_room_size: u16,
        socket_id: c_int,
    ) -> *mut rte_mempool;

    pub fn rte_pktmbuf_alloc(mp: *mut rte_mempool) -> *mut rte_mbuf;
    pub fn rte_pktmbuf_free(m: *mut rte_mbuf);
    pub fn rte_pktmbuf_alloc_bulk(
        mp: *mut rte_mempool,
        mbufs: *mut *mut rte_mbuf,
        count: c_uint,
    ) -> c_int;

    pub fn rte_eth_dev_count_avail() -> u16;
    pub fn rte_eth_dev_configure(
        port_id: PortId,
        nb_rx_queue: u16,
        nb_tx_queue: u16,
        eth_conf: *const rte_eth_conf,
    ) -> c_int;
    pub fn rte_eth_dev_info_get(port_id: PortId, dev_info: *mut rte_eth_dev_info) -> c_int;
    pub fn rte_eth_dev_start(port_id: PortId) -> c_int;
    pub fn rte_eth_dev_stop(port_id: PortId) -> c_int;
    pub fn rte_eth_dev_close(port_id: PortId) -> c_int;

    pub fn rte_eth_rx_queue_setup(
        port_id: PortId,
        rx_queue_id: QueueId,
        nb_rx_desc: u16,
        socket_id: c_uint,
        rx_conf: *const rte_eth_rxconf,
        mp: *mut rte_mempool,
    ) -> c_int;

    pub fn rte_eth_tx_queue_setup(
        port_id: PortId,
        tx_queue_id: QueueId,
        nb_tx_desc: u16,
        socket_id: c_uint,
        tx_conf: *const rte_eth_txconf,
    ) -> c_int;

    pub fn rte_eth_rx_burst(
        port_id: PortId,
        queue_id: QueueId,
        rx_pkts: *mut *mut rte_mbuf,
        nb_pkts: u16,
    ) -> u16;

    pub fn rte_eth_tx_burst(
        port_id: PortId,
        queue_id: QueueId,
        tx_pkts: *mut *mut rte_mbuf,
        nb_pkts: u16,
    ) -> u16;

    pub fn rte_eth_promiscuous_enable(port_id: PortId) -> c_int;
    pub fn rte_eth_macaddr_get(port_id: PortId, mac_addr: *mut rte_ether_addr) -> c_int;

    pub fn rte_pktmbuf_mtod(m: *const rte_mbuf) -> *mut c_void;
    pub fn rte_pktmbuf_data_len(m: *const rte_mbuf) -> u16;
    pub fn rte_pktmbuf_pkt_len(m: *const rte_mbuf) -> u32;
    pub fn rte_pktmbuf_append(m: *mut rte_mbuf, len: u16) -> *mut c_char;
    pub fn rte_pktmbuf_prepend(m: *mut rte_mbuf, len: u16) -> *mut c_char;
    pub fn rte_pktmbuf_adj(m: *mut rte_mbuf, len: u16) -> *mut c_char;
    pub fn rte_pktmbuf_trim(m: *mut rte_mbuf, len: u16) -> c_int;
}

/// Simulated DPDK functions for non-DPDK builds
#[cfg(not(feature = "dpdk"))]
pub mod sim {
    use super::*;
    use std::ptr;

    /// # Safety
    /// Simulated EAL init - safe as it does nothing.
    pub unsafe fn rte_eal_init(_argc: c_int, _argv: *mut *mut c_char) -> c_int {
        0 // Success
    }

    /// # Safety
    /// Simulated EAL cleanup - safe as it does nothing.
    pub unsafe fn rte_eal_cleanup() -> c_int {
        0
    }

    pub fn rte_lcore_id() -> LcoreId {
        0
    }

    pub fn rte_lcore_count() -> c_uint {
        1
    }

    pub fn rte_eth_dev_count_avail() -> u16 {
        0
    }

    /// # Safety
    /// Simulated mempool create - returns null, safe as it does nothing.
    pub unsafe fn rte_pktmbuf_pool_create(
        _name: *const c_char,
        _n: c_uint,
        _cache_size: c_uint,
        _priv_size: u16,
        _data_room_size: u16,
        _socket_id: c_int,
    ) -> *mut rte_mempool {
        ptr::null_mut()
    }

    /// # Safety
    /// Simulated RX burst - returns 0 packets, safe as it does nothing.
    pub unsafe fn rte_eth_rx_burst(
        _port_id: PortId,
        _queue_id: QueueId,
        _rx_pkts: *mut *mut rte_mbuf,
        _nb_pkts: u16,
    ) -> u16 {
        0
    }

    /// # Safety
    /// Simulated TX burst - returns 0 packets sent, safe as it does nothing.
    pub unsafe fn rte_eth_tx_burst(
        _port_id: PortId,
        _queue_id: QueueId,
        _tx_pkts: *mut *mut rte_mbuf,
        _nb_pkts: u16,
    ) -> u16 {
        0
    }
}
