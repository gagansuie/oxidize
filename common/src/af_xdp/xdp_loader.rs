//! XDP Program Loader for AF_XDP Packet Redirection
//!
//! Loads a minimal XDP BPF program that redirects UDP packets on the configured
//! port to AF_XDP sockets for zero-copy processing.

use std::ffi::CString;
use std::io::{self, Error};
use std::mem;
use std::os::unix::io::RawFd;
use std::ptr;

use tracing::{debug, error, info, warn};

// BPF syscall constants
const BPF_SYSCALL: i64 = 321; // x86_64
const BPF_MAP_CREATE: u32 = 0;
const BPF_MAP_UPDATE_ELEM: u32 = 2;
const BPF_PROG_LOAD: u32 = 5;
const BPF_LINK_CREATE: u32 = 28;

// BPF map types
const BPF_MAP_TYPE_XSKMAP: u32 = 17;

// BPF program types
const BPF_PROG_TYPE_XDP: u32 = 6;

// XDP attach types
const BPF_XDP: u32 = 37;

// XDP flags
#[allow(dead_code)]
const XDP_FLAGS_UPDATE_IF_NOEXIST: u32 = 1 << 0;
const XDP_FLAGS_SKB_MODE: u32 = 1 << 1;
const XDP_FLAGS_DRV_MODE: u32 = 1 << 2;

// BPF instruction encoding
const BPF_LD: u8 = 0x00;
const BPF_LDX: u8 = 0x01;
#[allow(dead_code)]
const BPF_ST: u8 = 0x02;
#[allow(dead_code)]
const BPF_STX: u8 = 0x03;
#[allow(dead_code)]
const BPF_ALU: u8 = 0x04;
const BPF_JMP: u8 = 0x05;
const BPF_ALU64: u8 = 0x07;

const BPF_W: u8 = 0x00;
const BPF_H: u8 = 0x08;
const BPF_B: u8 = 0x10;
const BPF_DW: u8 = 0x18;

const BPF_IMM: u8 = 0x00;
#[allow(dead_code)]
const BPF_ABS: u8 = 0x20;
#[allow(dead_code)]
const BPF_IND: u8 = 0x40;
const BPF_MEM: u8 = 0x60;
#[allow(dead_code)]
const BPF_ATOMIC: u8 = 0xc0;

#[allow(dead_code)]
const BPF_ADD: u8 = 0x00;
#[allow(dead_code)]
const BPF_SUB: u8 = 0x10;
#[allow(dead_code)]
const BPF_AND: u8 = 0x50;
#[allow(dead_code)]
const BPF_RSH: u8 = 0x70;
const BPF_MOV: u8 = 0xb0;

const BPF_K: u8 = 0x00;
const BPF_X: u8 = 0x08;

#[allow(dead_code)]
const BPF_JA: u8 = 0x00;
const BPF_JEQ: u8 = 0x10;
const BPF_JNE: u8 = 0x50;
const BPF_JLT: u8 = 0xa0;
const BPF_CALL: u8 = 0x80;
const BPF_EXIT: u8 = 0x90;

// BPF helper functions
#[allow(non_upper_case_globals)]
const BPF_FUNC_redirect_map: i32 = 51;
#[allow(dead_code, non_upper_case_globals)]
const BPF_FUNC_xdp_adjust_meta: i32 = 54;

// XDP actions
#[allow(dead_code)]
const XDP_ABORTED: i32 = 0;
#[allow(dead_code)]
const XDP_DROP: i32 = 1;
const XDP_PASS: i32 = 2;
#[allow(dead_code)]
const XDP_TX: i32 = 3;
#[allow(dead_code)]
const XDP_REDIRECT: i32 = 4;

/// BPF instruction
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct BpfInsn {
    code: u8,
    dst_src: u8, // dst:4 | src:4
    off: i16,
    imm: i32,
}

impl BpfInsn {
    fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        BpfInsn {
            code,
            dst_src: (src << 4) | (dst & 0xf),
            off,
            imm,
        }
    }
}

/// BPF attribute union for syscalls
#[repr(C)]
union BpfAttr {
    map_create: BpfMapCreate,
    map_elem: BpfMapElem,
    prog_load: BpfProgLoad,
    link_create: BpfLinkCreate,
    raw_tracepoint: BpfRawTracepoint,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfMapCreate {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfMapElem {
    map_fd: u32,
    key: u64,
    value_or_next_key: u64,
    flags: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfProgLoad {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_prog_fd_or_btf_obj_fd: u32,
    core_relo_cnt: u32,
    fd_array: u64,
    core_relos: u64,
    core_relo_rec_size: u32,
    log_true_size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfLinkCreate {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
    target_btf_id: u32,
    _padding: [u32; 11],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfRawTracepoint {
    name: u64,
    prog_fd: u32,
}

/// XDP Program Manager
pub struct XdpProgram {
    prog_fd: RawFd,
    xskmap_fd: RawFd,
    ifindex: u32,
    link_fd: Option<RawFd>,
    attached: bool,
}

impl XdpProgram {
    /// Create and load XDP program for the given interface and port
    pub fn new(interface: &str, port: u16, max_sockets: u32) -> io::Result<Self> {
        info!(
            "Loading XDP program for {} (port {}, max {} sockets)",
            interface, port, max_sockets
        );

        let ifindex = Self::get_ifindex(interface)?;

        // Create XSKMAP
        let xskmap_fd = Self::create_xskmap(max_sockets)?;
        info!("Created XSKMAP with fd={}", xskmap_fd);

        // Generate and load XDP program
        let prog_fd = Self::load_xdp_program(xskmap_fd, port)?;
        info!("Loaded XDP program with fd={}", prog_fd);

        Ok(XdpProgram {
            prog_fd,
            xskmap_fd,
            ifindex,
            link_fd: None,
            attached: false,
        })
    }

    /// Attach XDP program to interface (allows SKB fallback)
    pub fn attach(&mut self, skb_mode: bool) -> io::Result<()> {
        self.attach_internal(skb_mode, true)
    }

    /// Attach XDP program to interface without any fallback
    pub fn attach_no_fallback(&mut self, skb_mode: bool) -> io::Result<()> {
        self.attach_internal(skb_mode, false)
    }

    fn attach_internal(&mut self, skb_mode: bool, allow_fallback: bool) -> io::Result<()> {
        if self.attached {
            return Ok(());
        }

        let flags = if skb_mode {
            XDP_FLAGS_SKB_MODE
        } else {
            XDP_FLAGS_DRV_MODE
        };

        // Try netlink-based attach first (newer kernels)
        match self.attach_netlink(flags) {
            Ok(()) => {
                self.attached = true;
                info!("XDP program attached via netlink");
                return Ok(());
            }
            Err(e) => {
                debug!("Netlink attach failed: {}, trying setsockopt", e);
            }
        }

        // Fall back to bpf_link
        match self.attach_link() {
            Ok(()) => {
                self.attached = true;
                info!("XDP program attached via bpf_link");
                return Ok(());
            }
            Err(e) => {
                warn!("BPF link attach failed: {}", e);
            }
        }

        // Optional fallback to SKB mode
        if !skb_mode && allow_fallback {
            info!("Retrying with SKB mode...");
            return self.attach_internal(true, false);
        }

        Err(Error::other("Failed to attach XDP program"))
    }

    fn attach_netlink(&self, flags: u32) -> io::Result<()> {
        // Use if_nametoindex + raw netlink for XDP attach
        let sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if sock < 0 {
            return Err(Error::last_os_error());
        }

        // Build netlink message for XDP attach
        #[repr(C)]
        struct NlMsgHdr {
            nlmsg_len: u32,
            nlmsg_type: u16,
            nlmsg_flags: u16,
            nlmsg_seq: u32,
            nlmsg_pid: u32,
        }

        #[repr(C)]
        struct IfInfoMsg {
            ifi_family: u8,
            _pad: u8,
            ifi_type: u16,
            ifi_index: i32,
            ifi_flags: u32,
            ifi_change: u32,
        }

        #[repr(C)]
        struct RtAttr {
            rta_len: u16,
            rta_type: u16,
        }

        const RTM_SETLINK: u16 = 19;
        const NLM_F_REQUEST: u16 = 1;
        const NLM_F_ACK: u16 = 4;
        const IFLA_XDP: u16 = 43;
        const IFLA_XDP_FD: u16 = 1;
        const IFLA_XDP_FLAGS: u16 = 3;

        let mut buf = [0u8; 256];
        let mut offset = 0usize;

        // nlmsghdr
        let nlh = NlMsgHdr {
            nlmsg_len: 0, // filled later
            nlmsg_type: RTM_SETLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &nlh as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                mem::size_of::<NlMsgHdr>(),
            );
        }
        offset += mem::size_of::<NlMsgHdr>();

        // ifinfomsg
        let ifi = IfInfoMsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: self.ifindex as i32,
            ifi_flags: 0,
            ifi_change: 0,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &ifi as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                mem::size_of::<IfInfoMsg>(),
            );
        }
        offset += mem::size_of::<IfInfoMsg>();

        // IFLA_XDP nested attribute
        let xdp_start = offset;
        let xdp_attr = RtAttr {
            rta_len: 0,                     // filled later
            rta_type: IFLA_XDP | (1 << 15), // NLA_F_NESTED
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &xdp_attr as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                mem::size_of::<RtAttr>(),
            );
        }
        offset += mem::size_of::<RtAttr>();

        // IFLA_XDP_FD
        let fd_attr = RtAttr {
            rta_len: (mem::size_of::<RtAttr>() + 4) as u16,
            rta_type: IFLA_XDP_FD,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &fd_attr as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                mem::size_of::<RtAttr>(),
            );
        }
        offset += mem::size_of::<RtAttr>();
        unsafe {
            ptr::copy_nonoverlapping(
                &self.prog_fd as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                4,
            );
        }
        offset += 4;
        // Align to 4 bytes
        offset = (offset + 3) & !3;

        // IFLA_XDP_FLAGS
        let flags_attr = RtAttr {
            rta_len: (mem::size_of::<RtAttr>() + 4) as u16,
            rta_type: IFLA_XDP_FLAGS,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &flags_attr as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                mem::size_of::<RtAttr>(),
            );
        }
        offset += mem::size_of::<RtAttr>();
        unsafe {
            ptr::copy_nonoverlapping(
                &flags as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                4,
            );
        }
        offset += 4;
        offset = (offset + 3) & !3;

        // Update IFLA_XDP length
        let xdp_len = (offset - xdp_start) as u16;
        unsafe {
            ptr::copy_nonoverlapping(
                &xdp_len as *const _ as *const u8,
                buf.as_mut_ptr().add(xdp_start),
                2,
            );
        }

        // Update nlmsg_len
        let nlmsg_len = offset as u32;
        unsafe {
            ptr::copy_nonoverlapping(&nlmsg_len as *const _ as *const u8, buf.as_mut_ptr(), 4);
        }

        // Send message
        let sent = unsafe { libc::send(sock, buf.as_ptr() as *const libc::c_void, offset, 0) };
        if sent < 0 {
            unsafe { libc::close(sock) };
            return Err(Error::last_os_error());
        }

        // Receive ACK
        let mut resp = [0u8; 256];
        let recvd =
            unsafe { libc::recv(sock, resp.as_mut_ptr() as *mut libc::c_void, resp.len(), 0) };
        unsafe { libc::close(sock) };

        if recvd < 0 {
            return Err(Error::last_os_error());
        }

        // Check for error in response
        if recvd >= mem::size_of::<NlMsgHdr>() as isize {
            let resp_nlh: NlMsgHdr = unsafe { ptr::read(resp.as_ptr() as *const NlMsgHdr) };
            if resp_nlh.nlmsg_type == 2 {
                // NLMSG_ERROR
                let err: i32 = unsafe {
                    ptr::read(resp.as_ptr().add(mem::size_of::<NlMsgHdr>()) as *const i32)
                };
                if err != 0 {
                    return Err(Error::from_raw_os_error(-err));
                }
            }
        }

        Ok(())
    }

    fn attach_link(&mut self) -> io::Result<()> {
        let mut attr: BpfAttr = unsafe { mem::zeroed() };
        attr.link_create = BpfLinkCreate {
            prog_fd: self.prog_fd as u32,
            target_fd: self.ifindex,
            attach_type: BPF_XDP,
            flags: 0,
            target_btf_id: 0,
            _padding: [0; 11],
        };

        let ret = unsafe {
            libc::syscall(
                BPF_SYSCALL,
                BPF_LINK_CREATE,
                &attr as *const _ as *const libc::c_void,
                mem::size_of::<BpfLinkCreate>(),
            )
        };

        if ret < 0 {
            return Err(Error::last_os_error());
        }

        self.link_fd = Some(ret as RawFd);
        Ok(())
    }

    /// Register an AF_XDP socket in the XSKMAP
    pub fn register_socket(&self, queue_id: u32, socket_fd: RawFd) -> io::Result<()> {
        let mut attr: BpfAttr = unsafe { mem::zeroed() };
        let key = queue_id;
        let value = socket_fd;

        attr.map_elem = BpfMapElem {
            map_fd: self.xskmap_fd as u32,
            key: &key as *const _ as u64,
            value_or_next_key: &value as *const _ as u64,
            flags: 0,
        };

        let ret = unsafe {
            libc::syscall(
                BPF_SYSCALL,
                BPF_MAP_UPDATE_ELEM,
                &attr as *const _ as *const libc::c_void,
                mem::size_of::<BpfMapElem>(),
            )
        };

        if ret < 0 {
            return Err(Error::last_os_error());
        }

        info!(
            "Registered AF_XDP socket fd={} for queue {}",
            socket_fd, queue_id
        );
        Ok(())
    }

    fn create_xskmap(max_entries: u32) -> io::Result<RawFd> {
        let mut attr: BpfAttr = unsafe { mem::zeroed() };
        let mut name = [0u8; 16];
        let name_str = b"oxidize_xskmap";
        name[..name_str.len()].copy_from_slice(name_str);

        attr.map_create = BpfMapCreate {
            map_type: BPF_MAP_TYPE_XSKMAP,
            key_size: 4,   // u32 queue index
            value_size: 4, // u32 socket fd
            max_entries,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: name,
            map_ifindex: 0,
            btf_fd: 0,
            btf_key_type_id: 0,
            btf_value_type_id: 0,
            btf_vmlinux_value_type_id: 0,
            map_extra: 0,
        };

        let ret = unsafe {
            libc::syscall(
                BPF_SYSCALL,
                BPF_MAP_CREATE,
                &attr as *const _ as *const libc::c_void,
                mem::size_of::<BpfMapCreate>(),
            )
        };

        if ret < 0 {
            return Err(Error::last_os_error());
        }

        Ok(ret as RawFd)
    }

    fn load_xdp_program(xskmap_fd: RawFd, port: u16) -> io::Result<RawFd> {
        // Generate BPF bytecode for XDP redirect program
        let insns = Self::generate_xdp_bytecode(xskmap_fd, port);

        let license = CString::new("GPL").unwrap();
        let mut prog_name = [0u8; 16];
        let name_str = b"oxidize_xdp";
        prog_name[..name_str.len()].copy_from_slice(name_str);

        // Allocate log buffer for debugging
        let mut log_buf = vec![0u8; 65536];

        let mut attr: BpfAttr = unsafe { mem::zeroed() };
        attr.prog_load = BpfProgLoad {
            prog_type: BPF_PROG_TYPE_XDP,
            insn_cnt: insns.len() as u32,
            insns: insns.as_ptr() as u64,
            license: license.as_ptr() as u64,
            log_level: 1,
            log_size: log_buf.len() as u32,
            log_buf: log_buf.as_mut_ptr() as u64,
            kern_version: 0,
            prog_flags: 0,
            prog_name,
            prog_ifindex: 0,
            expected_attach_type: 0,
            prog_btf_fd: 0,
            func_info_rec_size: 0,
            func_info: 0,
            func_info_cnt: 0,
            line_info_rec_size: 0,
            line_info: 0,
            line_info_cnt: 0,
            attach_btf_id: 0,
            attach_prog_fd_or_btf_obj_fd: 0,
            core_relo_cnt: 0,
            fd_array: 0,
            core_relos: 0,
            core_relo_rec_size: 0,
            log_true_size: 0,
        };

        let ret = unsafe {
            libc::syscall(
                BPF_SYSCALL,
                BPF_PROG_LOAD,
                &attr as *const _ as *const libc::c_void,
                mem::size_of::<BpfProgLoad>(),
            )
        };

        if ret < 0 {
            // Print verifier log on failure
            let log_str = String::from_utf8_lossy(&log_buf);
            let log_trimmed = log_str.trim_end_matches('\0');
            if !log_trimmed.is_empty() {
                error!("BPF verifier log:\n{}", log_trimmed);
            }
            return Err(Error::last_os_error());
        }

        Ok(ret as RawFd)
    }

    /// Generate XDP bytecode that redirects UDP packets on OxTunnel port to XSKMAP
    ///
    /// SAFETY: This program is designed to be fail-safe. ANY error or unexpected
    /// condition results in XDP_PASS, ensuring network connectivity is never broken.
    ///
    /// Supports both IPv4 and IPv6:
    /// - IPv4: Eth(14) + IP(20) + UDP(8) = 42 bytes min, ports at offset 34/36
    /// - IPv6: Eth(14) + IPv6(40) + UDP(8) = 62 bytes min, ports at offset 54/56
    ///
    /// Only packets matching ALL criteria are redirected to AF_XDP.
    /// Everything else goes to XDP_PASS.
    fn generate_xdp_bytecode(xskmap_fd: RawFd, port: u16) -> Vec<BpfInsn> {
        let port_be = port.to_be() as i32;

        // Ethertypes in little-endian (as read from memory on x86)
        const ETHERTYPE_IPV4_LE: i32 = 0x0008; // 0x0800 in network order
        const ETHERTYPE_IPV6_LE: i32 = 0xDD86; // 0x86DD in network order

        // Program layout with dual IPv4/IPv6 support (35 instructions, indices 0-34):
        //
        // COMMON (0-6):
        //   0: r6 = r1
        //   1: r2 = ctx->data
        //   2: r3 = ctx->data_end
        //   3: r4 = r2
        //   4: r4 += 42
        //   5: if r3 < r4 goto PASS
        //   6: r4 = ethertype
        //
        // BRANCH (7-8):
        //   7: if r4 == IPv6 goto IPv6_PATH (19)
        //   8: if r4 != IPv4 goto PASS
        //
        // IPv4 PATH (9-18):
        //   9:  r4 = version/IHL
        //   10: r4 &= 0x0F
        //   11: if r4 != 5 goto PASS
        //   12: r4 = protocol
        //   13: if r4 != 17 goto PASS
        //   14: r4 = dst_port
        //   15: if r4 == port goto REDIRECT
        //   16: r4 = src_port
        //   17: if r4 == port goto REDIRECT
        //   18: goto PASS
        //
        // IPv6 PATH (19-26):
        //   19: r4 = r2
        //   20: r4 += 62
        //   21: if r3 < r4 goto PASS
        //   22: r4 = next_header
        //   23: if r4 != 17 goto PASS
        //   24: r4 = dst_port
        //   25: if r4 == port goto REDIRECT
        //   26: r4 = src_port
        //   27: if r4 != port goto PASS
        //
        // REDIRECT (28-32):
        //   28-29: r1 = map_fd
        //   30: r2 = rx_queue_index
        //   31: r3 = flags (must be 0 for redirect_map)
        //   32: call redirect_map
        //   33: exit
        //
        // PASS (34-35):
        //   34: r0 = XDP_PASS
        //   35: exit

        vec![
            // === COMMON SETUP (0-6) ===
            // 0: r6 = r1 (save context)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 6, 1, 0, 0),
            // 1: r2 = ctx->data
            BpfInsn::new(BPF_LDX | BPF_W | BPF_MEM, 2, 6, 0, 0),
            // 2: r3 = ctx->data_end
            BpfInsn::new(BPF_LDX | BPF_W | BPF_MEM, 3, 6, 4, 0),
            // 3: r4 = r2
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 4, 2, 0, 0),
            // 4: r4 += 42
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 4, 0, 0, 42),
            // 5: if r3 < r4 goto PASS (34), offset = 34 - 5 - 1 = 28
            BpfInsn::new(BPF_JMP | BPF_JLT | BPF_X, 3, 4, 28, 0),
            // 6: r4 = ethertype
            BpfInsn::new(BPF_LDX | BPF_H | BPF_MEM, 4, 2, 12, 0),
            // === BRANCH (7-8) ===
            // 7: if r4 == IPv6 goto IPv6_PATH (19), offset = 19 - 7 - 1 = 11
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 11, ETHERTYPE_IPV6_LE),
            // 8: if r4 != IPv4 goto PASS (34), offset = 34 - 8 - 1 = 25
            BpfInsn::new(BPF_JMP | BPF_JNE | BPF_K, 4, 0, 25, ETHERTYPE_IPV4_LE),
            // === IPv4 PATH (9-18) ===
            // 9: r4 = version/IHL
            BpfInsn::new(BPF_LDX | BPF_B | BPF_MEM, 4, 2, 14, 0),
            // 10: r4 &= 0x0F
            BpfInsn::new(BPF_ALU64 | BPF_AND | BPF_K, 4, 0, 0, 0x0F),
            // 11: if r4 != 5 goto PASS (34), offset = 34 - 11 - 1 = 22
            BpfInsn::new(BPF_JMP | BPF_JNE | BPF_K, 4, 0, 22, 5),
            // 12: r4 = protocol
            BpfInsn::new(BPF_LDX | BPF_B | BPF_MEM, 4, 2, 23, 0),
            // 13: if r4 != 17 goto PASS (34), offset = 34 - 13 - 1 = 20
            BpfInsn::new(BPF_JMP | BPF_JNE | BPF_K, 4, 0, 20, 17),
            // 14: r4 = dst_port (offset 36 = Eth14 + IP20 + 2)
            BpfInsn::new(BPF_LDX | BPF_H | BPF_MEM, 4, 2, 36, 0),
            // 15: if r4 == port goto REDIRECT (28), offset = 28 - 15 - 1 = 12
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 12, port_be),
            // 16: r4 = src_port (offset 34)
            BpfInsn::new(BPF_LDX | BPF_H | BPF_MEM, 4, 2, 34, 0),
            // 17: if r4 == port goto REDIRECT (28), offset = 28 - 17 - 1 = 10
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 10, port_be),
            // 18: goto PASS (34), offset = 34 - 18 - 1 = 15
            BpfInsn::new(BPF_JMP | BPF_JA, 0, 0, 15, 0),
            // === IPv6 PATH (19-27) ===
            // 19: r4 = r2
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_X, 4, 2, 0, 0),
            // 20: r4 += 62
            BpfInsn::new(BPF_ALU64 | BPF_ADD | BPF_K, 4, 0, 0, 62),
            // 21: if r3 < r4 goto PASS (34), offset = 34 - 21 - 1 = 12
            BpfInsn::new(BPF_JMP | BPF_JLT | BPF_X, 3, 4, 12, 0),
            // 22: r4 = next_header (offset 20 = Eth14 + IPv6 byte 6)
            BpfInsn::new(BPF_LDX | BPF_B | BPF_MEM, 4, 2, 20, 0),
            // 23: if r4 != 17 goto PASS (34), offset = 34 - 23 - 1 = 10
            BpfInsn::new(BPF_JMP | BPF_JNE | BPF_K, 4, 0, 10, 17),
            // 24: r4 = dst_port (offset 56 = Eth14 + IPv6_40 + 2)
            BpfInsn::new(BPF_LDX | BPF_H | BPF_MEM, 4, 2, 56, 0),
            // 25: if r4 == port goto REDIRECT (28), offset = 28 - 25 - 1 = 2
            BpfInsn::new(BPF_JMP | BPF_JEQ | BPF_K, 4, 0, 2, port_be),
            // 26: r4 = src_port (offset 54)
            BpfInsn::new(BPF_LDX | BPF_H | BPF_MEM, 4, 2, 54, 0),
            // 27: if r4 != port goto PASS (34), offset = 34 - 27 - 1 = 6
            BpfInsn::new(BPF_JMP | BPF_JNE | BPF_K, 4, 0, 6, port_be),
            // === REDIRECT (28-33) ===
            // 28-29: r1 = map_fd
            BpfInsn::new(BPF_LD | BPF_DW | BPF_IMM, 1, 1, 0, xskmap_fd),
            BpfInsn::new(0, 0, 0, 0, 0),
            // 30: r2 = rx_queue_index
            BpfInsn::new(BPF_LDX | BPF_W | BPF_MEM, 2, 6, 16, 0),
            // 31: r3 = flags (must be 0 for redirect_map)
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 3, 0, 0, 0),
            // 32: call redirect_map
            BpfInsn::new(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_redirect_map),
            // 33: exit
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
            // === PASS (34-35) ===
            // 34: r0 = XDP_PASS
            BpfInsn::new(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, XDP_PASS),
            // 35: exit
            BpfInsn::new(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
        ]
    }

    fn get_ifindex(interface: &str) -> io::Result<u32> {
        let ifname = CString::new(interface)
            .map_err(|_| Error::new(io::ErrorKind::InvalidInput, "Invalid interface name"))?;
        let idx = unsafe { libc::if_nametoindex(ifname.as_ptr()) };
        if idx == 0 {
            Err(Error::last_os_error())
        } else {
            Ok(idx)
        }
    }

    pub fn xskmap_fd(&self) -> RawFd {
        self.xskmap_fd
    }

    pub fn prog_fd(&self) -> RawFd {
        self.prog_fd
    }
}

impl Drop for XdpProgram {
    fn drop(&mut self) {
        info!("Detaching XDP program");

        // Close link if using bpf_link
        if let Some(fd) = self.link_fd {
            unsafe {
                libc::close(fd);
            }
        }

        // Detach from interface via netlink (set fd=-1)
        let _ = self.detach_netlink();

        // Close fds
        unsafe {
            libc::close(self.prog_fd);
            libc::close(self.xskmap_fd);
        }
    }
}

impl XdpProgram {
    fn detach_netlink(&self) -> io::Result<()> {
        let sock = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
        if sock < 0 {
            return Err(Error::last_os_error());
        }

        #[repr(C)]
        struct NlMsgHdr {
            nlmsg_len: u32,
            nlmsg_type: u16,
            nlmsg_flags: u16,
            nlmsg_seq: u32,
            nlmsg_pid: u32,
        }

        #[repr(C)]
        struct IfInfoMsg {
            ifi_family: u8,
            _pad: u8,
            ifi_type: u16,
            ifi_index: i32,
            ifi_flags: u32,
            ifi_change: u32,
        }

        #[repr(C)]
        struct RtAttr {
            rta_len: u16,
            rta_type: u16,
        }

        const RTM_SETLINK: u16 = 19;
        const NLM_F_REQUEST: u16 = 1;
        const NLM_F_ACK: u16 = 4;
        const IFLA_XDP: u16 = 43;
        const IFLA_XDP_FD: u16 = 1;

        let mut buf = [0u8; 128];
        let mut offset = 0usize;

        let nlh = NlMsgHdr {
            nlmsg_len: 0,
            nlmsg_type: RTM_SETLINK,
            nlmsg_flags: NLM_F_REQUEST | NLM_F_ACK,
            nlmsg_seq: 2,
            nlmsg_pid: 0,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &nlh as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                mem::size_of::<NlMsgHdr>(),
            );
        }
        offset += mem::size_of::<NlMsgHdr>();

        let ifi = IfInfoMsg {
            ifi_family: libc::AF_UNSPEC as u8,
            _pad: 0,
            ifi_type: 0,
            ifi_index: self.ifindex as i32,
            ifi_flags: 0,
            ifi_change: 0,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &ifi as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                mem::size_of::<IfInfoMsg>(),
            );
        }
        offset += mem::size_of::<IfInfoMsg>();

        let xdp_start = offset;
        let xdp_attr = RtAttr {
            rta_len: 0,
            rta_type: IFLA_XDP | (1 << 15),
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &xdp_attr as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                mem::size_of::<RtAttr>(),
            );
        }
        offset += mem::size_of::<RtAttr>();

        let fd_attr = RtAttr {
            rta_len: (mem::size_of::<RtAttr>() + 4) as u16,
            rta_type: IFLA_XDP_FD,
        };
        unsafe {
            ptr::copy_nonoverlapping(
                &fd_attr as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                mem::size_of::<RtAttr>(),
            );
        }
        offset += mem::size_of::<RtAttr>();
        let detach_fd: i32 = -1;
        unsafe {
            ptr::copy_nonoverlapping(
                &detach_fd as *const _ as *const u8,
                buf.as_mut_ptr().add(offset),
                4,
            );
        }
        offset += 4;
        offset = (offset + 3) & !3;

        let xdp_len = (offset - xdp_start) as u16;
        unsafe {
            ptr::copy_nonoverlapping(
                &xdp_len as *const _ as *const u8,
                buf.as_mut_ptr().add(xdp_start),
                2,
            );
        }

        let nlmsg_len = offset as u32;
        unsafe {
            ptr::copy_nonoverlapping(&nlmsg_len as *const _ as *const u8, buf.as_mut_ptr(), 4);
        }

        let _ = unsafe { libc::send(sock, buf.as_ptr() as *const libc::c_void, offset, 0) };
        unsafe { libc::close(sock) };

        Ok(())
    }
}
