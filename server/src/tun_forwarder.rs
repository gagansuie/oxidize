use anyhow::{Context, Result};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::Ipv4Addr;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info};

/// Shared TUN-based packet forwarder for relaying client traffic to the internet
/// Uses kernel TUN device + NAT for full protocol support (TCP, UDP, ICMP)
/// This is a singleton shared across all connections
pub struct SharedTunForwarder {
    /// TUN file descriptor for writes (separate from reader to avoid lock contention)
    tun_write_fd: Arc<std::sync::Mutex<std::fs::File>>,
    /// Map of client source IPs to connection IDs for routing responses
    ip_to_conn: Arc<RwLock<HashMap<u32, u64>>>,
    /// Receiver for responses - connections register to receive their responses
    response_subscribers: Arc<RwLock<HashMap<u64, mpsc::Sender<Vec<u8>>>>>,
    /// Packet counter for logging
    write_count: std::sync::atomic::AtomicU64,
}

impl SharedTunForwarder {
    /// Create and initialize the shared TUN forwarder at server startup
    pub async fn new() -> Result<Arc<Self>> {
        let ip_to_conn = Arc::new(RwLock::new(HashMap::new()));
        let response_subscribers = Arc::new(RwLock::new(HashMap::new()));

        // Create TUN device
        let mut config = tun::Configuration::default();
        config
            .address((10, 200, 200, 254))
            .netmask((255, 255, 255, 0))
            .mtu(1400)
            .up();

        #[cfg(target_os = "linux")]
        config.platform(|cfg| {
            cfg.packet_information(false);
        });

        #[cfg(target_os = "linux")]
        config.name("oxrelay0");

        let dev = tun::create(&config).context("Failed to create TUN device")?;

        // Get raw fd and duplicate for separate read/write handles
        let raw_fd = dev.as_raw_fd();
        let write_fd = unsafe { libc::dup(raw_fd) };
        if write_fd < 0 {
            return Err(anyhow::anyhow!("Failed to dup TUN fd"));
        }
        let write_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
        let tun_write_fd = Arc::new(std::sync::Mutex::new(write_file));

        info!("✅ Server TUN interface created: oxrelay0");
        info!("   Address: 10.200.200.254/24");

        // Setup NAT
        setup_nat()?;

        let forwarder = Arc::new(Self {
            tun_write_fd,
            ip_to_conn: ip_to_conn.clone(),
            response_subscribers: response_subscribers.clone(),
            write_count: std::sync::atomic::AtomicU64::new(0),
        });

        // Start reader task with original device (separate fd)
        let ip_to_conn_reader = ip_to_conn.clone();
        let subs_reader = response_subscribers.clone();

        tokio::task::spawn_blocking(move || {
            run_tun_reader(dev, ip_to_conn_reader, subs_reader);
        });

        info!("Shared TUN forwarder initialized");
        Ok(forwarder)
    }

    /// Register a connection to receive response packets
    /// Also maps the client's TUN IP (10.200.200.1) to this connection for response routing
    pub async fn register_connection(&self, conn_id: u64) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(4096);
        self.response_subscribers.write().await.insert(conn_id, tx);

        // Map client TUN IP to this connection for response routing
        // Client TUN is 10.200.200.1 - responses to this IP go to this connection
        let client_tun_ip = u32::from_be_bytes([10, 200, 200, 1]);
        self.ip_to_conn.write().await.insert(client_tun_ip, conn_id);

        info!(
            "Connection {} registered for TUN responses (10.200.200.1)",
            conn_id
        );
        rx
    }

    /// Unregister a connection
    #[allow(dead_code)]
    pub async fn unregister_connection(&self, conn_id: u64) {
        self.response_subscribers.write().await.remove(&conn_id);
    }

    /// Forward an IP packet to the internet via TUN - direct write
    pub async fn forward(&self, _conn_id: u64, packet: Vec<u8>) -> Result<()> {
        if packet.len() < 20 {
            return Ok(());
        }

        // Extract IPs for logging
        let src_ip = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]);
        let dst_ip = u32::from_be_bytes([packet[16], packet[17], packet[18], packet[19]]);
        let protocol = packet[9];

        let count = self
            .write_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if count.is_multiple_of(1000) {
            info!(
                "TUN write #{}: proto={} {}→{} ({} bytes)",
                count,
                protocol,
                Ipv4Addr::from(src_ip),
                Ipv4Addr::from(dst_ip),
                packet.len()
            );
        }

        // Note: Client TUN IP (10.200.200.1) is mapped to conn_id in register_connection()
        // No need to map src_ip here since responses always come to client TUN IP

        // Direct write to TUN using spawn_blocking (separate fd from reader)
        let write_fd = self.tun_write_fd.clone();
        tokio::task::spawn_blocking(move || {
            if let Ok(mut file) = write_fd.lock() {
                if let Err(e) = file.write_all(&packet) {
                    error!("TUN write error: {}", e);
                }
            }
        })
        .await?;

        Ok(())
    }
}

/// TUN reader task - reads responses from TUN and dispatches to clients
fn run_tun_reader(
    mut tun_dev: tun::platform::Device,
    ip_to_conn: Arc<RwLock<HashMap<u32, u64>>>,
    response_subscribers: Arc<RwLock<HashMap<u64, mpsc::Sender<Vec<u8>>>>>,
) {
    info!("📥 TUN reader task started");
    let mut buffer = vec![0u8; 1500];
    let mut count: u64 = 0;

    loop {
        let len = match tun_dev.read(&mut buffer) {
            Ok(len) if len > 0 => len,
            Ok(_) => continue,
            Err(e) => {
                error!("TUN read error: {}", e);
                continue;
            }
        };

        if len < 20 {
            continue;
        }

        count += 1;

        // Extract IPs
        let src_ip = u32::from_be_bytes([buffer[12], buffer[13], buffer[14], buffer[15]]);
        let dst_ip = u32::from_be_bytes([buffer[16], buffer[17], buffer[18], buffer[19]]);

        // Find connection ID for this destination (client IP)
        let conn_id = {
            if let Ok(map) = ip_to_conn.try_read() {
                map.get(&dst_ip).copied()
            } else {
                None
            }
        };

        if let Some(conn_id) = conn_id {
            let packet = buffer[..len].to_vec();
            if let Ok(subs) = response_subscribers.try_read() {
                if let Some(tx) = subs.get(&conn_id) {
                    let _ = tx.blocking_send(packet);
                }
            }
        } else if count.is_multiple_of(1000) {
            info!(
                "📥 TUN read #{}: {}→{} (no mapping for dst)",
                count,
                Ipv4Addr::from(src_ip),
                Ipv4Addr::from(dst_ip)
            );
        }
    }
}

/// Setup NAT/masquerading for outbound traffic
fn setup_nat() -> Result<()> {
    use std::process::Command;

    info!("Setting up NAT/masquerading...");

    // IP forwarding is enabled in entrypoint.sh via /proc writes
    // Just verify it's enabled
    if let Ok(contents) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward") {
        info!("   IP forwarding: {}", contents.trim());
    }

    // Get default interface
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    let route_output = String::from_utf8_lossy(&output.stdout);
    let default_iface = route_output
        .split_whitespace()
        .skip_while(|s| *s != "dev")
        .nth(1)
        .unwrap_or("eth0");

    info!("   Default interface: {}", default_iface);

    // Setup iptables NAT (ignore errors if rules already exist)
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-o",
            default_iface,
            "-j",
            "MASQUERADE",
        ])
        .output();

    let _ = Command::new("iptables")
        .args(["-A", "FORWARD", "-i", "oxrelay0", "-j", "ACCEPT"])
        .output();

    let _ = Command::new("iptables")
        .args([
            "-A",
            "FORWARD",
            "-o",
            "oxrelay0",
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ])
        .output();

    info!("✅ NAT configured");
    Ok(())
}
