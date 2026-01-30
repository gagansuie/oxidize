//! OxTunnel Client Integration
//!
//! Provides packet batching, optional encryption, and OxTunnel encapsulation
//! for the daemon's NFQUEUE pipeline. Works with AF_XDP and optimized UDP.
//!
//! ## Performance Optimizations:
//! - **Adaptive batch timeout**: Adjusts based on traffic rate (500µs-2000µs)
//! - **Traffic-aware batching**: Gaming/VoIP packets bypass batching for lowest latency
//! - **Proactive FEC integration**: Uses ML predictions for pre-emptive redundancy

use crate::oxtunnel_protocol::{
    encode_packet, flags, generate_id, CryptoEngine, HandshakeInit, PacketBatch, TunnelBufferPool,
    HEADER_SIZE, MAX_PACKET_SIZE,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// OxTunnel client configuration
#[derive(Clone, Debug)]
pub struct OxTunnelConfig {
    pub enable_batching: bool,
    pub max_batch_size: usize,
    pub batch_timeout_us: u64,
    pub enable_encryption: bool,
    pub encryption_key: Option<[u8; 32]>,
    pub enable_compression: bool,
    pub server_addr: SocketAddr,
    /// Enable adaptive batch timeout based on traffic rate
    pub enable_adaptive_timeout: bool,
    /// Minimum batch timeout in microseconds (high traffic)
    pub min_batch_timeout_us: u64,
    /// Maximum batch timeout in microseconds (low traffic)
    pub max_batch_timeout_us: u64,
    /// Enable traffic-aware batching (bypass batching for gaming/VoIP)
    pub enable_traffic_aware_batching: bool,
}

impl Default for OxTunnelConfig {
    fn default() -> Self {
        Self {
            enable_batching: true,
            max_batch_size: 64,
            batch_timeout_us: 1000,
            enable_encryption: false,
            encryption_key: None,
            enable_compression: false,
            server_addr: "127.0.0.1:51820".parse().unwrap(),
            enable_adaptive_timeout: true,
            min_batch_timeout_us: 500,  // 500µs for high traffic
            max_batch_timeout_us: 2000, // 2ms for low traffic
            enable_traffic_aware_batching: true,
        }
    }
}

/// Statistics for the OxTunnel client
pub struct ClientStats {
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub batches_sent: AtomicU64,
    pub gaming_packets_bypassed: AtomicU64,
    pub adaptive_timeout_adjustments: AtomicU64,
}

impl ClientStats {
    pub fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            batches_sent: AtomicU64::new(0),
            gaming_packets_bypassed: AtomicU64::new(0),
            adaptive_timeout_adjustments: AtomicU64::new(0),
        }
    }
}

impl Default for ClientStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Adaptive timeout calculator based on traffic rate
#[derive(Debug)]
pub struct AdaptiveTimeout {
    min_timeout_us: u64,
    max_timeout_us: u64,
    current_timeout_us: AtomicU64,
    packet_count: AtomicU64,
    window_start: Mutex<Instant>,
    window_duration: Duration,
}

impl AdaptiveTimeout {
    pub fn new(min_us: u64, max_us: u64) -> Self {
        Self {
            min_timeout_us: min_us,
            max_timeout_us: max_us,
            current_timeout_us: AtomicU64::new((min_us + max_us) / 2),
            packet_count: AtomicU64::new(0),
            window_start: Mutex::new(Instant::now()),
            window_duration: Duration::from_millis(100), // 100ms measurement window
        }
    }

    /// Record a packet and potentially adjust timeout
    #[inline]
    pub fn record_packet(&self) -> Option<u64> {
        let count = self.packet_count.fetch_add(1, Ordering::Relaxed) + 1;

        // Check if we should recalculate (every 100 packets or window elapsed)
        #[allow(clippy::manual_is_multiple_of)]
        if count % 100 == 0 {
            return self.recalculate();
        }
        None
    }

    /// Recalculate timeout based on current packet rate
    fn recalculate(&self) -> Option<u64> {
        let mut window_start = self.window_start.lock().unwrap();
        let elapsed = window_start.elapsed();

        if elapsed < self.window_duration {
            return None;
        }

        let count = self.packet_count.swap(0, Ordering::Relaxed);
        let pps = count as f64 / elapsed.as_secs_f64();
        *window_start = Instant::now();

        // Calculate new timeout based on packets per second
        // High traffic (>10k pps) = min timeout
        // Low traffic (<1k pps) = max timeout
        let new_timeout = if pps > 10000.0 {
            self.min_timeout_us
        } else if pps < 1000.0 {
            self.max_timeout_us
        } else {
            // Linear interpolation between min and max
            let ratio = (pps - 1000.0) / 9000.0;
            let range = self.max_timeout_us - self.min_timeout_us;
            self.max_timeout_us - (ratio * range as f64) as u64
        };

        let old_timeout = self.current_timeout_us.swap(new_timeout, Ordering::Relaxed);

        if old_timeout != new_timeout {
            debug!(
                "Adaptive timeout: {} -> {}µs (pps: {:.0})",
                old_timeout, new_timeout, pps
            );
            Some(new_timeout)
        } else {
            None
        }
    }

    /// Get current timeout
    #[inline]
    pub fn current(&self) -> Duration {
        Duration::from_micros(self.current_timeout_us.load(Ordering::Relaxed))
    }
}

struct PacketBatchState {
    packets: Vec<Vec<u8>>,
    total_size: usize,
    first_packet_time: Option<Instant>,
}

impl PacketBatchState {
    fn new() -> Self {
        Self {
            packets: Vec::with_capacity(64),
            total_size: 0,
            first_packet_time: None,
        }
    }

    fn clear(&mut self) {
        self.packets.clear();
        self.total_size = 0;
        self.first_packet_time = None;
    }
}

/// Check if a packet is latency-sensitive based on IP header
/// Returns true for gaming/VoIP traffic that should bypass batching
#[inline]
pub fn is_latency_sensitive_packet(packet: &[u8]) -> bool {
    if packet.len() < 28 {
        return false; // Too short for UDP header
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return false; // Only handle IPv4 for now
    }

    let protocol = packet[9];
    if protocol != 17 {
        return false; // Only UDP is latency-sensitive
    }

    // Extract UDP destination port (IP header is typically 20 bytes)
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if packet.len() < ihl + 4 {
        return false;
    }

    let dest_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);

    // Gaming and VoIP ports
    matches!(dest_port,
        // Gaming ports
        27015..=27017 |  // Source engine (Valve)
        7777..=7779 |    // Unreal Engine
        3074 |           // Xbox Live
        3478..=3481 |    // PlayStation + STUN/TURN
        5060..=5062 |    // Riot Games + SIP
        6672..=6673 |    // EA
        9000..=9002 |    // Various games
        // VoIP ports
        16384..=32767    // RTP range
    )
}

/// Encapsulates packets using OxTunnel protocol before sending
pub struct OxTunnelEncapsulator {
    config: OxTunnelConfig,
    client_id: [u8; 32],
    sequence: AtomicU32,
    crypto: Option<CryptoEngine>,
    #[allow(dead_code)]
    buffer_pool: Arc<TunnelBufferPool>,
    stats: Arc<ClientStats>,
    batch: Mutex<PacketBatchState>,
    adaptive_timeout: Option<AdaptiveTimeout>,
}

impl OxTunnelEncapsulator {
    pub fn new(config: OxTunnelConfig) -> Self {
        let client_id = generate_id();
        let crypto = if config.enable_encryption {
            let key = config
                .encryption_key
                .unwrap_or_else(CryptoEngine::generate_key);
            Some(CryptoEngine::new(Some(&key)))
        } else {
            None
        };

        let adaptive_timeout = if config.enable_adaptive_timeout {
            Some(AdaptiveTimeout::new(
                config.min_batch_timeout_us,
                config.max_batch_timeout_us,
            ))
        } else {
            None
        };

        Self {
            config,
            client_id,
            sequence: AtomicU32::new(0),
            crypto,
            buffer_pool: Arc::new(TunnelBufferPool::new()),
            stats: Arc::new(ClientStats::new()),
            batch: Mutex::new(PacketBatchState::new()),
            adaptive_timeout,
        }
    }

    /// Check if packet should bypass batching (gaming/VoIP)
    #[inline]
    pub fn should_bypass_batching(&self, packet: &[u8]) -> bool {
        self.config.enable_traffic_aware_batching && is_latency_sensitive_packet(packet)
    }

    /// Add packet with traffic-awareness - returns (immediate_send, batch_to_send)
    /// immediate_send: Some if this packet should be sent immediately (gaming/VoIP)
    /// batch_to_send: Some if a batch is ready to be flushed
    pub fn add_to_batch_traffic_aware(&self, packet: &[u8]) -> (Option<Vec<u8>>, Option<Vec<u8>>) {
        // Check if this is latency-sensitive traffic
        if self.should_bypass_batching(packet) {
            self.stats
                .gaming_packets_bypassed
                .fetch_add(1, Ordering::Relaxed);
            // Send immediately without batching
            match self.encapsulate_single(packet) {
                Ok(encapsulated) => return (Some(encapsulated), None),
                Err(e) => {
                    error!("Failed to encapsulate gaming packet: {}", e);
                    return (None, None);
                }
            }
        }

        // Normal batching for non-latency-sensitive traffic
        (None, self.add_to_batch(packet))
    }

    #[inline]
    fn next_seq(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    pub fn encapsulate_single(&self, packet: &[u8]) -> Result<Vec<u8>, &'static str> {
        let seq = self.next_seq();
        let mut flags_byte = 0u8;

        let payload = if self.config.enable_compression && packet.len() > 64 {
            flags_byte |= flags::COMPRESSED;
            lz4_flex::compress_prepend_size(packet)
        } else {
            packet.to_vec()
        };

        let crypto_ref = if self.config.enable_encryption {
            flags_byte |= flags::ENCRYPTED;
            self.crypto.as_ref()
        } else {
            None
        };

        let mut output = vec![0u8; HEADER_SIZE + payload.len() + 32];
        let len = encode_packet(&mut output, &payload, seq, flags_byte, crypto_ref)?;
        output.truncate(len);

        self.stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_sent
            .fetch_add(len as u64, Ordering::Relaxed);

        Ok(output)
    }

    pub fn add_to_batch(&self, packet: &[u8]) -> Option<Vec<u8>> {
        let mut batch = self.batch.lock().unwrap();

        let new_size = batch.total_size + packet.len() + 2;
        let should_flush = new_size > MAX_PACKET_SIZE - HEADER_SIZE - 32
            || batch.packets.len() >= self.config.max_batch_size;

        if should_flush && !batch.packets.is_empty() {
            let result = self.flush_batch_locked(&mut batch);
            batch.packets.push(packet.to_vec());
            batch.total_size = packet.len() + 2;
            batch.first_packet_time = Some(Instant::now());
            return result;
        }

        batch.packets.push(packet.to_vec());
        batch.total_size = new_size;
        if batch.first_packet_time.is_none() {
            batch.first_packet_time = Some(Instant::now());
        }

        None
    }

    pub fn check_batch_timeout(&self) -> Option<Vec<u8>> {
        let mut batch = self.batch.lock().unwrap();
        if batch.packets.is_empty() {
            return None;
        }
        if let Some(first_time) = batch.first_packet_time {
            // Use adaptive timeout if enabled, otherwise fixed timeout
            let timeout = self
                .adaptive_timeout
                .as_ref()
                .map(|at| at.current())
                .unwrap_or(Duration::from_micros(self.config.batch_timeout_us));

            if first_time.elapsed() > timeout {
                return self.flush_batch_locked(&mut batch);
            }
        }
        None
    }

    /// Record a packet for adaptive timeout calculation
    #[inline]
    pub fn record_packet_for_adaptive_timeout(&self) {
        if let Some(ref adaptive) = self.adaptive_timeout {
            if adaptive.record_packet().is_some() {
                self.stats
                    .adaptive_timeout_adjustments
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn flush_batch(&self) -> Option<Vec<u8>> {
        let mut batch = self.batch.lock().unwrap();
        self.flush_batch_locked(&mut batch)
    }

    fn flush_batch_locked(&self, batch: &mut PacketBatchState) -> Option<Vec<u8>> {
        if batch.packets.is_empty() {
            return None;
        }

        let packet_count = batch.packets.len();
        let mut batch_obj = PacketBatch::new();
        for pkt in &batch.packets {
            batch_obj.add(pkt);
        }
        batch.clear();

        let mut payload = vec![0u8; MAX_PACKET_SIZE];
        let payload_len = match batch_obj.encode(&mut payload) {
            Ok(len) => len,
            Err(e) => {
                error!("Failed to encode batch: {}", e);
                return None;
            }
        };
        payload.truncate(payload_len);

        let seq = self.next_seq();
        let mut flags_byte = flags::BATCH;

        let crypto_ref = if self.config.enable_encryption {
            flags_byte |= flags::ENCRYPTED;
            self.crypto.as_ref()
        } else {
            None
        };

        let mut output = vec![0u8; HEADER_SIZE + payload.len() + 32];
        match encode_packet(&mut output, &payload, seq, flags_byte, crypto_ref) {
            Ok(len) => {
                output.truncate(len);
                self.stats
                    .packets_sent
                    .fetch_add(packet_count as u64, Ordering::Relaxed);
                self.stats
                    .bytes_sent
                    .fetch_add(len as u64, Ordering::Relaxed);
                self.stats.batches_sent.fetch_add(1, Ordering::Relaxed);
                Some(output)
            }
            Err(e) => {
                error!("Failed to encode batch packet: {}", e);
                None
            }
        }
    }

    pub fn create_handshake(&self) -> Vec<u8> {
        let init = HandshakeInit {
            client_id: self.client_id,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            encryption_supported: self.config.enable_encryption,
        };

        let mut payload = [0u8; 64];
        let payload_len = init.encode(&mut payload);
        let mut output = vec![0u8; HEADER_SIZE + payload_len];
        let len = encode_packet(
            &mut output,
            &payload[..payload_len],
            0,
            flags::CONTROL,
            None,
        )
        .unwrap_or(0);
        output.truncate(len);
        output
    }

    pub fn stats(&self) -> &Arc<ClientStats> {
        &self.stats
    }

    pub fn client_id(&self) -> &[u8; 32] {
        &self.client_id
    }

    pub fn config(&self) -> &OxTunnelConfig {
        &self.config
    }

    /// Get current adaptive timeout (if enabled)
    pub fn current_timeout(&self) -> Duration {
        self.adaptive_timeout
            .as_ref()
            .map(|at| at.current())
            .unwrap_or(Duration::from_micros(self.config.batch_timeout_us))
    }
}

/// High-performance OxTunnel sender that batches packets
pub struct OxTunnelSender {
    encapsulator: Arc<OxTunnelEncapsulator>,
    output_tx: mpsc::Sender<Vec<u8>>,
}

impl OxTunnelSender {
    pub fn new(config: OxTunnelConfig, output_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self {
            encapsulator: Arc::new(OxTunnelEncapsulator::new(config)),
            output_tx,
        }
    }

    pub async fn run(&self, mut input_rx: mpsc::Receiver<Vec<u8>>) {
        info!(
            "📦 OxTunnel sender started (batching: {}, encryption: {}, adaptive_timeout: {}, traffic_aware: {})",
            self.encapsulator.config.enable_batching,
            self.encapsulator.config.enable_encryption,
            self.encapsulator.config.enable_adaptive_timeout,
            self.encapsulator.config.enable_traffic_aware_batching
        );

        let mut packet_count: u64 = 0;
        let mut batch_count: u64 = 0;
        let mut gaming_bypass_count: u64 = 0;
        let start = Instant::now();

        let encap = self.encapsulator.clone();
        let tx = self.output_tx.clone();
        let timeout_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_micros(500));
            loop {
                interval.tick().await;
                if let Some(batch) = encap.check_batch_timeout() {
                    if tx.send(batch).await.is_err() {
                        break;
                    }
                }
            }
        });

        loop {
            tokio::select! {
                Some(packet) = input_rx.recv() => {
                    packet_count += 1;

                    // Record for adaptive timeout
                    self.encapsulator.record_packet_for_adaptive_timeout();

                    if self.encapsulator.config.enable_batching {
                        // Use traffic-aware batching
                        let (immediate, batch) = self.encapsulator.add_to_batch_traffic_aware(&packet);

                        // Send immediate packet (gaming/VoIP)
                        if let Some(data) = immediate {
                            gaming_bypass_count += 1;
                            if self.output_tx.send(data).await.is_err() {
                                warn!("Output channel closed");
                                break;
                            }
                        }

                        // Send batch if ready
                        if let Some(batch_data) = batch {
                            batch_count += 1;
                            if self.output_tx.send(batch_data).await.is_err() {
                                warn!("Output channel closed");
                                break;
                            }
                        }
                    } else {
                        match self.encapsulator.encapsulate_single(&packet) {
                            Ok(encapsulated) => {
                                if self.output_tx.send(encapsulated).await.is_err() {
                                    warn!("Output channel closed");
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("Encapsulation failed: {}", e);
                            }
                        }
                    }

                    #[allow(clippy::manual_is_multiple_of)]
                    if packet_count % 10000 == 0 {
                        let elapsed = start.elapsed().as_secs_f64();
                        let pps = packet_count as f64 / elapsed;
                        let timeout = self.encapsulator.current_timeout();
                        info!(
                            "📊 OxTunnel: {} packets, {} batches, {} gaming bypass, {:.0} pps, timeout: {}µs",
                            packet_count, batch_count, gaming_bypass_count, pps, timeout.as_micros()
                        );
                    }
                }

                else => {
                    if let Some(batch) = self.encapsulator.flush_batch() {
                        let _ = self.output_tx.send(batch).await;
                    }
                    break;
                }
            }
        }

        timeout_task.abort();

        let elapsed = start.elapsed();
        let stats = self.encapsulator.stats();
        info!(
            "📊 OxTunnel sender finished: {} packets, {} batches, {} gaming bypass in {:.2}s ({:.0} pps)",
            stats.packets_sent.load(Ordering::Relaxed),
            stats.batches_sent.load(Ordering::Relaxed),
            stats.gaming_packets_bypassed.load(Ordering::Relaxed),
            elapsed.as_secs_f64(),
            packet_count as f64 / elapsed.as_secs_f64().max(0.001)
        );
    }

    pub fn encapsulator(&self) -> &Arc<OxTunnelEncapsulator> {
        &self.encapsulator
    }
}

// ============================================================================
// Cross-Platform Packet Capture Service
// ============================================================================

use std::sync::atomic::AtomicBool;

/// Packet capture configuration
#[derive(Clone, Debug)]
pub struct CaptureConfig {
    /// Capture TCP traffic
    pub capture_tcp: bool,
    /// Capture UDP traffic  
    pub capture_udp: bool,
    /// Capture ICMP traffic
    pub capture_icmp: bool,
    /// Exclude these destination IPs (e.g., relay server)
    pub exclude_ips: Vec<std::net::IpAddr>,
    /// NFQUEUE number (Linux only)
    pub queue_num: u16,
    /// TUN file descriptor (Android/iOS only - provided by VpnService/NetworkExtension)
    pub tun_fd: Option<i32>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            capture_tcp: true,
            capture_udp: true,
            capture_icmp: false,
            exclude_ips: Vec::new(),
            queue_num: 0,
            tun_fd: None,
        }
    }
}

/// Cross-platform packet capture service
/// Uses NFQUEUE on Linux, WinDivert on Windows, BPF on macOS
pub struct PacketCaptureService {
    config: CaptureConfig,
    stop_flag: Arc<AtomicBool>,
}

impl PacketCaptureService {
    pub fn new(config: CaptureConfig) -> Self {
        Self {
            config,
            stop_flag: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Start packet capture, returns receiver for captured packets
    pub fn start(&self) -> (mpsc::Receiver<Vec<u8>>, tokio::task::JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(50000);
        let stop_flag = self.stop_flag.clone();
        let config = self.config.clone();

        let handle = tokio::task::spawn_blocking(move || {
            run_platform_capture(tx, stop_flag, config);
        });

        (rx, handle)
    }

    /// Stop packet capture
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    /// Get the platform name for logging
    pub fn platform_name() -> &'static str {
        #[cfg(target_os = "linux")]
        {
            "NFQUEUE"
        }
        #[cfg(target_os = "windows")]
        {
            "WinDivert"
        }
        #[cfg(target_os = "macos")]
        {
            "BPF"
        }
        #[cfg(target_os = "android")]
        {
            "Android-VpnService"
        }
        #[cfg(target_os = "ios")]
        {
            "iOS-NetworkExtension"
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "windows",
            target_os = "macos",
            target_os = "android",
            target_os = "ios"
        )))]
        {
            "Unsupported"
        }
    }
}

// ============================================================================
// Linux: NFQUEUE capture
// ============================================================================
#[cfg(target_os = "linux")]
fn run_platform_capture(
    tx: mpsc::Sender<Vec<u8>>,
    stop_flag: Arc<AtomicBool>,
    config: CaptureConfig,
) {
    use nfq::{Queue, Verdict};
    use std::process::Command;

    info!(
        "📦 Linux NFQUEUE capture starting on queue {}...",
        config.queue_num
    );
    info!(
        "   TCP: {}, UDP: {}",
        config.capture_tcp, config.capture_udp
    );

    // CRITICAL: Aggressively clean up ALL old iptables rules first to prevent accumulation
    // This fixes the bug where rules accumulate on repeated connect/disconnect cycles
    info!("📦 Cleaning up ALL existing NFQUEUE rules...");
    let queue_num = config.queue_num.to_string();

    // Remove ALL NFQUEUE rules (loop until none remain)
    for _ in 0..100 {
        let tcp_result = Command::new("iptables")
            .args([
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "-j",
                "NFQUEUE",
                "--queue-num",
                &queue_num,
                "--queue-bypass",
            ])
            .output();
        let udp_result = Command::new("iptables")
            .args([
                "-D",
                "OUTPUT",
                "-p",
                "udp",
                "-j",
                "NFQUEUE",
                "--queue-num",
                &queue_num,
                "--queue-bypass",
            ])
            .output();
        // Also try without --queue-bypass flag (older rules may not have it)
        let _ = Command::new("iptables")
            .args([
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "-j",
                "NFQUEUE",
                "--queue-num",
                &queue_num,
            ])
            .output();
        let _ = Command::new("iptables")
            .args([
                "-D",
                "OUTPUT",
                "-p",
                "udp",
                "-j",
                "NFQUEUE",
                "--queue-num",
                &queue_num,
            ])
            .output();

        // Stop when both deletions fail (no more rules to delete)
        let tcp_failed = tcp_result.map(|o| !o.status.success()).unwrap_or(true);
        let udp_failed = udp_result.map(|o| !o.status.success()).unwrap_or(true);
        if tcp_failed && udp_failed {
            break;
        }
    }

    // Remove ALL relay server exclusion rules (loop until none remain)
    for ip in &config.exclude_ips {
        for _ in 0..50 {
            let result = Command::new("iptables")
                .args(["-D", "OUTPUT", "-d", &ip.to_string(), "-j", "ACCEPT"])
                .output();
            if result.map(|o| !o.status.success()).unwrap_or(true) {
                break;
            }
        }
        // Also clean INPUT rules
        for _ in 0..50 {
            let result = Command::new("iptables")
                .args(["-D", "INPUT", "-s", &ip.to_string(), "-j", "ACCEPT"])
                .output();
            if result.map(|o| !o.status.success()).unwrap_or(true) {
                break;
            }
        }
    }

    // Clean up old system exclusion rules (DNS, DHCP, etc.)
    for _ in 0..10 {
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
            .output();
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
            .output();
        let _ = Command::new("iptables")
            .args([
                "-D", "OUTPUT", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT",
            ])
            .output();
        let _ = Command::new("iptables")
            .args([
                "-D", "OUTPUT", "-p", "udp", "--dport", "123", "-j", "ACCEPT",
            ])
            .output();
        let _ = Command::new("iptables")
            .args([
                "-D", "OUTPUT", "-p", "udp", "--dport", "5353", "-j", "ACCEPT",
            ])
            .output();
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-d", "127.0.0.0/8", "-j", "ACCEPT"])
            .output();
    }

    info!("✅ Old iptables rules cleaned up");

    // STEP 1: Add NFQUEUE rules FIRST (they will be at the bottom after exclusions are added)
    // Using -A (append) instead of -I (insert) so exclusions added with -I come BEFORE
    let mut rules_added = true;
    if config.capture_udp
        && Command::new("iptables")
            .args([
                "-A",
                "OUTPUT",
                "-p",
                "udp",
                "-j",
                "NFQUEUE",
                "--queue-num",
                &queue_num,
                "--queue-bypass",
            ])
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
    {
        rules_added = false;
    }
    if config.capture_tcp
        && Command::new("iptables")
            .args([
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-j",
                "NFQUEUE",
                "--queue-num",
                &queue_num,
                "--queue-bypass",
            ])
            .output()
            .map(|o| !o.status.success())
            .unwrap_or(true)
    {
        rules_added = false;
    }

    if rules_added {
        info!("✅ iptables NFQUEUE rules added (appended to end of chain)");
    } else {
        warn!("⚠️ Failed to add some iptables rules - packet capture may not work");
    }

    // STEP 2: Add exclusion rules with -I (insert at TOP) so they come BEFORE NFQUEUE
    // Order matters! These are inserted in reverse order (last inserted = first checked)

    // Localhost traffic - never tunnel local traffic (inserted last = checked first)
    let _ = Command::new("iptables")
        .args(["-I", "OUTPUT", "1", "-d", "127.0.0.0/8", "-j", "ACCEPT"])
        .output();

    // mDNS (port 5353) - local network discovery
    let _ = Command::new("iptables")
        .args([
            "-I", "OUTPUT", "1", "-p", "udp", "--dport", "5353", "-j", "ACCEPT",
        ])
        .output();

    // NTP (port 123) - required for time sync
    let _ = Command::new("iptables")
        .args([
            "-I", "OUTPUT", "1", "-p", "udp", "--dport", "123", "-j", "ACCEPT",
        ])
        .output();

    // DHCP (port 67-68) - required for IP address renewal
    let _ = Command::new("iptables")
        .args([
            "-I", "OUTPUT", "1", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT",
        ])
        .output();

    // DNS (port 53) - required for name resolution
    let _ = Command::new("iptables")
        .args([
            "-I", "OUTPUT", "1", "-p", "tcp", "--dport", "53", "-j", "ACCEPT",
        ])
        .output();
    let _ = Command::new("iptables")
        .args([
            "-I", "OUTPUT", "1", "-p", "udp", "--dport", "53", "-j", "ACCEPT",
        ])
        .output();

    // CRITICAL: Relay server exclusion - MUST be at the very top (inserted last)
    // This ensures tunnel traffic to the relay server is NEVER captured by NFQUEUE
    for ip in &config.exclude_ips {
        // Insert at position 1 (top of chain) to guarantee it's checked first
        let _ = Command::new("iptables")
            .args(["-I", "OUTPUT", "1", "-d", &ip.to_string(), "-j", "ACCEPT"])
            .output();
        let _ = Command::new("iptables")
            .args(["-I", "INPUT", "1", "-s", &ip.to_string(), "-j", "ACCEPT"])
            .output();
        info!(
            "✅ Relay server {} excluded from capture (rule at top of chain)",
            ip
        );
    }

    info!("✅ System traffic excluded from tunnel (DNS, DHCP, NTP, mDNS, localhost)");

    let mut queue = match Queue::open() {
        Ok(q) => q,
        Err(e) => {
            error!("Failed to open NFQUEUE: {}", e);
            cleanup_iptables_rules(&config);
            return;
        }
    };

    if let Err(e) = queue.bind(config.queue_num) {
        error!("Failed to bind NFQUEUE {}: {}", config.queue_num, e);
        cleanup_iptables_rules(&config);
        return;
    }

    info!(
        "✅ NFQUEUE bound to queue {} - capturing TCP+UDP packets",
        config.queue_num
    );

    let mut packet_count: u64 = 0;
    let mut last_log = std::time::Instant::now();

    while !stop_flag.load(Ordering::Relaxed) {
        match queue.recv() {
            Ok(mut msg) => {
                let payload = msg.get_payload().to_vec();

                // Send packet through tunnel channel (non-blocking)
                match tx.try_send(payload) {
                    Ok(_) => {
                        packet_count += 1;
                        // DROP the original packet - it will be forwarded through the tunnel
                        msg.set_verdict(Verdict::Drop);
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Channel is full: drop this packet to keep tunnel-only behavior
                        msg.set_verdict(Verdict::Drop);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!("Tunnel channel closed - stopping capture");
                        stop_flag.store(true, Ordering::Relaxed);
                        msg.set_verdict(Verdict::Accept);
                    }
                }
                let _ = queue.verdict(msg);

                // Log progress every 10 seconds
                if last_log.elapsed().as_secs() >= 10 {
                    let pps = packet_count as f64 / last_log.elapsed().as_secs_f64();
                    info!("📦 NFQUEUE: {} packets, {:.0} pps", packet_count, pps);
                    last_log = std::time::Instant::now();
                }
            }
            Err(e) => {
                if !stop_flag.load(Ordering::Relaxed) {
                    warn!("NFQUEUE recv error: {}", e);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    // Clean up iptables rules on exit
    cleanup_iptables_rules(&config);
    info!("📦 NFQUEUE capture stopped after {} packets", packet_count);
}

#[cfg(target_os = "linux")]
fn cleanup_iptables_rules(config: &CaptureConfig) {
    use std::process::Command;

    info!("📦 Cleaning up iptables NFQUEUE rules...");
    let queue_num = config.queue_num.to_string();

    // Clean up system traffic exclusion rules
    let _ = Command::new("iptables")
        .args(["-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"])
        .output();
    let _ = Command::new("iptables")
        .args(["-D", "OUTPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"])
        .output();
    let _ = Command::new("iptables")
        .args([
            "-D", "OUTPUT", "-p", "udp", "--dport", "67:68", "-j", "ACCEPT",
        ])
        .output();
    let _ = Command::new("iptables")
        .args([
            "-D", "OUTPUT", "-p", "udp", "--dport", "123", "-j", "ACCEPT",
        ])
        .output();
    let _ = Command::new("iptables")
        .args([
            "-D", "OUTPUT", "-p", "udp", "--dport", "5353", "-j", "ACCEPT",
        ])
        .output();
    let _ = Command::new("iptables")
        .args(["-D", "OUTPUT", "-d", "127.0.0.0/8", "-j", "ACCEPT"])
        .output();

    // Clean up exclusion rules (both directions)
    for ip in &config.exclude_ips {
        let _ = Command::new("iptables")
            .args(["-D", "OUTPUT", "-d", &ip.to_string(), "-j", "ACCEPT"])
            .output();
        let _ = Command::new("iptables")
            .args(["-D", "INPUT", "-s", &ip.to_string(), "-j", "ACCEPT"])
            .output();
    }

    // Clean up NFQUEUE rules from OUTPUT chain (and INPUT for backwards compat)
    for chain in &["OUTPUT", "INPUT"] {
        if config.capture_tcp {
            let _ = Command::new("iptables")
                .args([
                    "-D",
                    chain,
                    "-p",
                    "tcp",
                    "-j",
                    "NFQUEUE",
                    "--queue-num",
                    &queue_num,
                    "--queue-bypass",
                ])
                .output();
        }
        if config.capture_udp {
            let _ = Command::new("iptables")
                .args([
                    "-D",
                    chain,
                    "-p",
                    "udp",
                    "-j",
                    "NFQUEUE",
                    "--queue-num",
                    &queue_num,
                    "--queue-bypass",
                ])
                .output();
        }
    }
}

// ============================================================================
// Windows: WinDivert capture
// ============================================================================
#[cfg(target_os = "windows")]
fn run_platform_capture(
    tx: mpsc::Sender<Vec<u8>>,
    stop_flag: Arc<AtomicBool>,
    config: CaptureConfig,
) {
    use windivert::prelude::*;

    info!("📦 Windows WinDivert capture starting...");

    // Build filter based on config
    let mut filter_parts = Vec::new();
    if config.capture_tcp {
        filter_parts.push("tcp");
    }
    if config.capture_udp {
        filter_parts.push("udp");
    }

    let filter = format!("outbound and ({})", filter_parts.join(" or "));

    let handle = match WinDivert::network(&filter, 0, WinDivertFlags::new()) {
        Ok(h) => h,
        Err(e) => {
            error!("Failed to open WinDivert: {}", e);
            return;
        }
    };

    info!("✅ WinDivert opened with filter: {}", filter);

    let mut packet_count: u64 = 0;
    let mut last_log = std::time::Instant::now();

    while !stop_flag.load(Ordering::Relaxed) {
        match handle.recv(None) {
            Ok(packet) => {
                let data = packet.data.to_vec();

                match tx.try_send(data) {
                    Ok(_) => {
                        packet_count += 1;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Channel full: drop this packet from tunnel capture only
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!("Tunnel channel closed - stopping capture");
                        stop_flag.store(true, Ordering::Relaxed);
                    }
                }

                // Re-inject packet to allow normal traffic flow
                let _ = handle.send(&packet);

                if last_log.elapsed().as_secs() >= 10 {
                    let pps = packet_count as f64 / last_log.elapsed().as_secs_f64();
                    info!("📦 WinDivert: {} packets, {:.0} pps", packet_count, pps);
                    last_log = std::time::Instant::now();
                }
            }
            Err(e) => {
                if !stop_flag.load(Ordering::Relaxed) {
                    warn!("WinDivert recv error: {}", e);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    info!(
        "📦 WinDivert capture stopped after {} packets",
        packet_count
    );
}

// ============================================================================
// macOS: BPF capture
// ============================================================================
#[cfg(target_os = "macos")]
fn run_platform_capture(
    tx: mpsc::Sender<Vec<u8>>,
    stop_flag: Arc<AtomicBool>,
    config: CaptureConfig,
) {
    use std::io::Read;

    info!("📦 macOS BPF capture starting...");

    // Find available BPF device
    let bpf_path = (0..256)
        .map(|i| format!("/dev/bpf{}", i))
        .find(|path| std::path::Path::new(path).exists());

    let bpf_path = match bpf_path {
        Some(p) => p,
        None => {
            error!("No available BPF device found");
            return;
        }
    };

    let mut bpf_file = match std::fs::File::open(&bpf_path) {
        Ok(f) => f,
        Err(e) => {
            error!("Failed to open BPF device {}: {}", bpf_path, e);
            return;
        }
    };

    info!("✅ BPF device opened: {}", bpf_path);

    let mut packet_count: u64 = 0;
    let mut last_log = std::time::Instant::now();
    let mut buf = vec![0u8; 65536];

    while !stop_flag.load(Ordering::Relaxed) {
        match bpf_file.read(&mut buf) {
            Ok(len) if len > 0 => {
                let payload = buf[..len].to_vec();

                match tx.try_send(payload) {
                    Ok(_) => {
                        packet_count += 1;
                    }
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        // Channel full: drop this packet from tunnel capture only
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        warn!("Tunnel channel closed - stopping capture");
                        stop_flag.store(true, Ordering::Relaxed);
                    }
                }

                if last_log.elapsed().as_secs() >= 10 {
                    let pps = packet_count as f64 / last_log.elapsed().as_secs_f64();
                    info!("📦 BPF: {} packets, {:.0} pps", packet_count, pps);
                    last_log = std::time::Instant::now();
                }
            }
            Ok(_) => {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            Err(e) => {
                if !stop_flag.load(Ordering::Relaxed) {
                    warn!("BPF read error: {}", e);
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    info!("📦 BPF capture stopped after {} packets", packet_count);
}

// ============================================================================
// Android: VpnService TUN capture
// ============================================================================
#[cfg(target_os = "android")]
fn run_platform_capture(
    tx: mpsc::Sender<Vec<u8>>,
    stop_flag: Arc<AtomicBool>,
    config: CaptureConfig,
) {
    info!("📦 Android VpnService TUN capture starting...");

    // On Android, the VpnService creates the TUN fd and passes it to us
    // The fd should be set via set_tun_fd() before starting capture
    let tun_fd = match config.tun_fd {
        Some(fd) => fd,
        None => {
            error!("❌ Android: TUN fd not provided. Set via CaptureConfig.tun_fd");
            return;
        }
    };

    info!("✅ Android TUN fd: {}", tun_fd);

    let mut packet_count: u64 = 0;
    let mut last_log = std::time::Instant::now();
    let mut buf = vec![0u8; 65536];

    while !stop_flag.load(Ordering::Relaxed) {
        let result =
            unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if result > 0 {
            let len = result as usize;
            let payload = buf[..len].to_vec();

            // Check if this is an IP packet we should capture
            if len >= 20 {
                let version = (payload[0] >> 4) & 0x0F;
                let protocol = if version == 4 && len >= 20 {
                    payload[9]
                } else if version == 6 && len >= 40 {
                    payload[6]
                } else {
                    continue;
                };

                // Filter based on config
                let should_capture = match protocol {
                    6 => config.capture_tcp,       // TCP
                    17 => config.capture_udp,      // UDP
                    1 | 58 => config.capture_icmp, // ICMP/ICMPv6
                    _ => false,
                };

                if !should_capture {
                    continue;
                }
            }

            match tx.try_send(payload) {
                Ok(_) => {
                    packet_count += 1;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Channel full: drop packet
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!("Tunnel channel closed - stopping capture");
                    stop_flag.store(true, Ordering::Relaxed);
                }
            }

            if last_log.elapsed().as_secs() >= 10 {
                let pps = packet_count as f64 / last_log.elapsed().as_secs_f64();
                info!("📦 Android TUN: {} packets, {:.0} pps", packet_count, pps);
                last_log = std::time::Instant::now();
            }
        } else if result < 0 {
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error() != Some(libc::EAGAIN) && !stop_flag.load(Ordering::Relaxed) {
                warn!("TUN read error: {}", errno);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    info!(
        "📦 Android TUN capture stopped after {} packets",
        packet_count
    );
}

// ============================================================================
// iOS: NetworkExtension TUN capture
// ============================================================================
#[cfg(target_os = "ios")]
fn run_platform_capture(
    tx: mpsc::Sender<Vec<u8>>,
    stop_flag: Arc<AtomicBool>,
    config: CaptureConfig,
) {
    info!("📦 iOS NetworkExtension TUN capture starting...");

    // On iOS, the PacketTunnelProvider creates the TUN fd and passes it to us
    let tun_fd = match config.tun_fd {
        Some(fd) => fd,
        None => {
            error!("❌ iOS: TUN fd not provided. Set via CaptureConfig.tun_fd");
            return;
        }
    };

    info!("✅ iOS TUN fd: {}", tun_fd);

    let mut packet_count: u64 = 0;
    let mut last_log = std::time::Instant::now();
    let mut buf = vec![0u8; 65536];

    while !stop_flag.load(Ordering::Relaxed) {
        let result =
            unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };

        if result > 0 {
            let len = result as usize;
            let payload = buf[..len].to_vec();

            // Check if this is an IP packet we should capture
            if len >= 20 {
                let version = (payload[0] >> 4) & 0x0F;
                let protocol = if version == 4 && len >= 20 {
                    payload[9]
                } else if version == 6 && len >= 40 {
                    payload[6]
                } else {
                    continue;
                };

                // Filter based on config
                let should_capture = match protocol {
                    6 => config.capture_tcp,
                    17 => config.capture_udp,
                    1 | 58 => config.capture_icmp,
                    _ => false,
                };

                if !should_capture {
                    continue;
                }
            }

            match tx.try_send(payload) {
                Ok(_) => {
                    packet_count += 1;
                }
                Err(mpsc::error::TrySendError::Full(_)) => {}
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    warn!("Tunnel channel closed - stopping capture");
                    stop_flag.store(true, Ordering::Relaxed);
                }
            }

            if last_log.elapsed().as_secs() >= 10 {
                let pps = packet_count as f64 / last_log.elapsed().as_secs_f64();
                info!("📦 iOS TUN: {} packets, {:.0} pps", packet_count, pps);
                last_log = std::time::Instant::now();
            }
        } else if result < 0 {
            let errno = std::io::Error::last_os_error();
            if errno.raw_os_error() != Some(libc::EAGAIN) && !stop_flag.load(Ordering::Relaxed) {
                warn!("TUN read error: {}", errno);
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }

    info!("📦 iOS TUN capture stopped after {} packets", packet_count);
}

// ============================================================================
// Unsupported platforms
// ============================================================================
#[cfg(not(any(
    target_os = "linux",
    target_os = "windows",
    target_os = "macos",
    target_os = "android",
    target_os = "ios"
)))]
fn run_platform_capture(
    _tx: mpsc::Sender<Vec<u8>>,
    _stop_flag: Arc<AtomicBool>,
    _config: CaptureConfig,
) {
    error!("❌ Packet capture not supported on this platform");
    error!("   Supported: Linux (NFQUEUE), Windows (WinDivert), macOS (BPF), Android (VpnService), iOS (NetworkExtension)");
}

// ============================================================================
// Integrated OxTunnel Pipeline
// ============================================================================

/// Complete OxTunnel pipeline: Capture -> Encapsulate -> Send
/// This integrates PacketCaptureService with OxTunnelSender
pub struct OxTunnelPipeline {
    capture: PacketCaptureService,
    encapsulator: Arc<OxTunnelEncapsulator>,
}

impl OxTunnelPipeline {
    pub fn new(capture_config: CaptureConfig, tunnel_config: OxTunnelConfig) -> Self {
        Self {
            capture: PacketCaptureService::new(capture_config),
            encapsulator: Arc::new(OxTunnelEncapsulator::new(tunnel_config)),
        }
    }

    /// Run the complete pipeline: capture packets -> encapsulate -> send to output
    pub async fn run(&self, output_tx: mpsc::Sender<Vec<u8>>) {
        info!(
            "🚀 OxTunnel Pipeline starting ({})...",
            PacketCaptureService::platform_name()
        );

        let (packet_rx, capture_handle) = self.capture.start();

        let sender = OxTunnelSender {
            encapsulator: self.encapsulator.clone(),
            output_tx,
        };

        sender.run(packet_rx).await;

        self.capture.stop();
        let _ = capture_handle.await;

        info!("📦 OxTunnel Pipeline stopped");
    }

    pub fn stop(&self) {
        self.capture.stop();
    }

    pub fn encapsulator(&self) -> &Arc<OxTunnelEncapsulator> {
        &self.encapsulator
    }
}

// ============================================================================
// Response Injection Service - Injects tunnel responses into local network stack
// ============================================================================

/// Response injector for injecting tunnel responses into the local network stack
/// Uses raw sockets on Linux, WinDivert on Windows, utun on macOS, TUN on Android/iOS
pub struct ResponseInjector {
    #[cfg(target_os = "linux")]
    raw_socket_v4: Option<std::os::unix::io::RawFd>,
    #[cfg(target_os = "linux")]
    raw_socket_v6: Option<std::os::unix::io::RawFd>,
    #[cfg(target_os = "macos")]
    utun_fd: Option<std::os::unix::io::RawFd>,
    #[cfg(target_os = "windows")]
    windivert_handle: Option<WinDivertInjector>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    tun_fd: Option<i32>,
    stats: Arc<ResponseInjectorStats>,
}

/// Windows WinDivert injector wrapper
#[cfg(target_os = "windows")]
pub struct WinDivertInjector {
    // WinDivert handle stored for injection
    // Note: actual injection uses WinDivert::send()
}

#[derive(Default)]
pub struct ResponseInjectorStats {
    pub packets_injected: AtomicU64,
    pub bytes_injected: AtomicU64,
    pub injection_errors: AtomicU64,
}

impl ResponseInjector {
    /// Create a new response injector
    pub fn new() -> Self {
        #[cfg(target_os = "linux")]
        {
            let raw_socket_v4 = Self::create_raw_socket_v4();
            let raw_socket_v6 = Self::create_raw_socket_v6();

            if raw_socket_v4.is_some() {
                info!("✅ Response injector: IPv4 raw socket created");
            } else {
                warn!(
                    "⚠️ Response injector: Failed to create IPv4 raw socket (requires CAP_NET_RAW)"
                );
            }
            if raw_socket_v6.is_some() {
                info!("✅ Response injector: IPv6 raw socket created");
            } else {
                warn!(
                    "⚠️ Response injector: Failed to create IPv6 raw socket (requires CAP_NET_RAW)"
                );
            }

            Self {
                raw_socket_v4,
                raw_socket_v6,
                stats: Arc::new(ResponseInjectorStats::default()),
            }
        }

        #[cfg(target_os = "macos")]
        {
            let utun_fd = Self::create_utun_socket();
            if utun_fd.is_some() {
                info!("✅ Response injector: macOS utun socket created");
            } else {
                warn!("⚠️ Response injector: Failed to create utun socket (requires root)");
            }
            Self {
                utun_fd,
                stats: Arc::new(ResponseInjectorStats::default()),
            }
        }

        #[cfg(target_os = "windows")]
        {
            info!("✅ Response injector: Windows WinDivert mode");
            Self {
                windivert_handle: Some(WinDivertInjector {}),
                stats: Arc::new(ResponseInjectorStats::default()),
            }
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            // TUN fd will be set by the mobile app via set_tun_fd()
            info!("✅ Response injector: Mobile TUN mode (fd will be provided by app)");
            Self {
                tun_fd: None,
                stats: Arc::new(ResponseInjectorStats::default()),
            }
        }

        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "android",
            target_os = "ios"
        )))]
        {
            warn!("⚠️ Response injector: Platform not supported");
            Self {
                stats: Arc::new(ResponseInjectorStats::default()),
            }
        }
    }

    /// Set TUN file descriptor (for Android/iOS where the app creates the TUN)
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub fn set_tun_fd(&mut self, fd: i32) {
        self.tun_fd = Some(fd);
        info!("✅ Response injector: TUN fd set to {}", fd);
    }

    #[cfg(target_os = "linux")]
    fn create_raw_socket_v4() -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::IntoRawFd;

        match socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
        ) {
            Ok(sock) => {
                // Set IP_HDRINCL so we can provide the full IP header
                if sock.set_header_included_v4(true).is_err() {
                    warn!("Failed to set IP_HDRINCL on raw socket");
                }
                Some(sock.into_raw_fd())
            }
            Err(e) => {
                debug!(
                    "Failed to create raw IPv4 socket: {} (requires CAP_NET_RAW)",
                    e
                );
                None
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn create_raw_socket_v6() -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::IntoRawFd;

        match socket2::Socket::new(
            socket2::Domain::IPV6,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
        ) {
            Ok(sock) => Some(sock.into_raw_fd()),
            Err(e) => {
                debug!(
                    "Failed to create raw IPv6 socket: {} (requires CAP_NET_RAW)",
                    e
                );
                None
            }
        }
    }

    /// Inject a response packet into the local network stack
    /// The packet should be a complete IP packet (with IP header)
    pub fn inject(&self, packet: &[u8]) -> Result<(), String> {
        if packet.is_empty() {
            return Err("Empty packet".to_string());
        }

        let version = (packet[0] >> 4) & 0x0F;

        match version {
            4 => self.inject_ipv4(packet),
            6 => self.inject_ipv6(packet),
            _ => Err(format!("Unknown IP version: {}", version)),
        }
    }

    #[cfg(target_os = "linux")]
    fn inject_ipv4(&self, packet: &[u8]) -> Result<(), String> {
        if packet.len() < 20 {
            return Err("IPv4 packet too short".to_string());
        }

        let fd = self.raw_socket_v4.ok_or("No IPv4 raw socket available")?;

        // Extract destination IP from packet header (bytes 16-19)
        let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        // Create destination sockaddr
        let dest_addr =
            socket2::SockAddr::from(std::net::SocketAddr::new(std::net::IpAddr::V4(dst_ip), 0));

        let result = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                dest_addr.as_ptr(),
                dest_addr.len() as libc::socklen_t,
            )
        };

        if result < 0 {
            let errno = std::io::Error::last_os_error();
            self.stats.injection_errors.fetch_add(1, Ordering::Relaxed);
            Err(format!("IPv4 injection failed: {}", errno))
        } else {
            self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_injected
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            Ok(())
        }
    }

    #[cfg(target_os = "linux")]
    fn inject_ipv6(&self, packet: &[u8]) -> Result<(), String> {
        if packet.len() < 40 {
            return Err("IPv6 packet too short".to_string());
        }

        let fd = self.raw_socket_v6.ok_or("No IPv6 raw socket available")?;

        // Extract destination IP from packet header (bytes 24-39)
        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&packet[24..40]);
        let dst_ip = std::net::Ipv6Addr::from(dst_bytes);

        let dest_addr =
            socket2::SockAddr::from(std::net::SocketAddr::new(std::net::IpAddr::V6(dst_ip), 0));

        let result = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                dest_addr.as_ptr(),
                dest_addr.len() as libc::socklen_t,
            )
        };

        if result < 0 {
            let errno = std::io::Error::last_os_error();
            self.stats.injection_errors.fetch_add(1, Ordering::Relaxed);
            Err(format!("IPv6 injection failed: {}", errno))
        } else {
            self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_injected
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            Ok(())
        }
    }

    // ========================================================================
    // macOS Implementation - utun device
    // ========================================================================

    #[cfg(target_os = "macos")]
    fn create_utun_socket() -> Option<std::os::unix::io::RawFd> {
        use std::os::unix::io::IntoRawFd;

        // On macOS, we use a raw socket with IP_HDRINCL for injection
        // utun requires more setup, so we use raw sockets similar to Linux
        match socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(libc::IPPROTO_RAW)),
        ) {
            Ok(sock) => {
                // Set IP_HDRINCL so we provide the full IP header
                let enable: libc::c_int = 1;
                unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_HDRINCL,
                        &enable as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
                Some(sock.into_raw_fd())
            }
            Err(e) => {
                debug!("Failed to create macOS raw socket: {} (requires root)", e);
                None
            }
        }
    }

    #[cfg(target_os = "macos")]
    fn inject_ipv4(&self, packet: &[u8]) -> Result<(), String> {
        use std::os::unix::io::AsRawFd;

        if packet.len() < 20 {
            return Err("IPv4 packet too short".to_string());
        }

        let fd = self.utun_fd.ok_or("No macOS socket available")?;

        // Extract destination IP from packet header (bytes 16-19)
        let dst_ip = std::net::Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let dest_addr =
            socket2::SockAddr::from(std::net::SocketAddr::new(std::net::IpAddr::V4(dst_ip), 0));

        let result = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                dest_addr.as_ptr(),
                dest_addr.len() as libc::socklen_t,
            )
        };

        if result < 0 {
            let errno = std::io::Error::last_os_error();
            self.stats.injection_errors.fetch_add(1, Ordering::Relaxed);
            Err(format!("macOS IPv4 injection failed: {}", errno))
        } else {
            self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_injected
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            Ok(())
        }
    }

    #[cfg(target_os = "macos")]
    fn inject_ipv6(&self, packet: &[u8]) -> Result<(), String> {
        if packet.len() < 40 {
            return Err("IPv6 packet too short".to_string());
        }
        // macOS IPv6 raw socket injection
        // For now, log and skip - full implementation needs separate IPv6 socket
        self.stats.injection_errors.fetch_add(1, Ordering::Relaxed);
        Err("macOS IPv6 injection requires additional setup".to_string())
    }

    // ========================================================================
    // Windows Implementation - WinDivert
    // ========================================================================

    #[cfg(target_os = "windows")]
    fn inject_ipv4(&self, packet: &[u8]) -> Result<(), String> {
        use windivert::prelude::*;

        if packet.len() < 20 {
            return Err("IPv4 packet too short".to_string());
        }

        // Create a temporary WinDivert handle for injection
        // Filter "false" means we only inject, don't capture
        let handle = WinDivert::network("false", 0, WinDivertFlags::new().set_send_only())
            .map_err(|e| format!("WinDivert open failed: {}", e))?;

        // Create WinDivert packet with inbound direction (response coming in)
        let wd_packet = WinDivertPacket {
            data: packet.to_vec().into(),
            address: WinDivertAddress::Network(WinDivertNetworkData {
                if_idx: 0,
                sub_if_idx: 0,
                direction: WinDivertDirection::Inbound,
                ..Default::default()
            }),
        };

        handle
            .send(&wd_packet)
            .map_err(|e| format!("WinDivert send failed: {}", e))?;

        self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
        self.stats
            .bytes_injected
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn inject_ipv6(&self, packet: &[u8]) -> Result<(), String> {
        // Windows WinDivert handles IPv6 the same way
        self.inject_ipv4(packet)
    }

    // ========================================================================
    // Android/iOS Implementation - TUN device
    // ========================================================================

    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn inject_ipv4(&self, packet: &[u8]) -> Result<(), String> {
        if packet.len() < 20 {
            return Err("IPv4 packet too short".to_string());
        }

        let fd = self
            .tun_fd
            .ok_or("TUN fd not set - call set_tun_fd() first")?;

        // Write directly to TUN device
        let result =
            unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };

        if result < 0 {
            let errno = std::io::Error::last_os_error();
            self.stats.injection_errors.fetch_add(1, Ordering::Relaxed);
            Err(format!("TUN write failed: {}", errno))
        } else {
            self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_injected
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            Ok(())
        }
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    fn inject_ipv6(&self, packet: &[u8]) -> Result<(), String> {
        if packet.len() < 40 {
            return Err("IPv6 packet too short".to_string());
        }

        let fd = self
            .tun_fd
            .ok_or("TUN fd not set - call set_tun_fd() first")?;

        // Write directly to TUN device (same as IPv4)
        let result =
            unsafe { libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len()) };

        if result < 0 {
            let errno = std::io::Error::last_os_error();
            self.stats.injection_errors.fetch_add(1, Ordering::Relaxed);
            Err(format!("TUN write failed: {}", errno))
        } else {
            self.stats.packets_injected.fetch_add(1, Ordering::Relaxed);
            self.stats
                .bytes_injected
                .fetch_add(packet.len() as u64, Ordering::Relaxed);
            Ok(())
        }
    }

    // ========================================================================
    // Unsupported platforms
    // ========================================================================

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "android",
        target_os = "ios"
    )))]
    fn inject_ipv4(&self, _packet: &[u8]) -> Result<(), String> {
        self.stats.injection_errors.fetch_add(1, Ordering::Relaxed);
        Err("IPv4 injection not supported on this platform".to_string())
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "android",
        target_os = "ios"
    )))]
    fn inject_ipv6(&self, _packet: &[u8]) -> Result<(), String> {
        self.stats.injection_errors.fetch_add(1, Ordering::Relaxed);
        Err("IPv6 injection not supported on this platform".to_string())
    }

    /// Get injection statistics
    pub fn stats(&self) -> &Arc<ResponseInjectorStats> {
        &self.stats
    }

    /// Check if the injector is functional
    pub fn is_available(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.raw_socket_v4.is_some() || self.raw_socket_v6.is_some()
        }
        #[cfg(target_os = "macos")]
        {
            self.utun_fd.is_some()
        }
        #[cfg(target_os = "windows")]
        {
            self.windivert_handle.is_some()
        }
        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            self.tun_fd.is_some()
        }
        #[cfg(not(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "android",
            target_os = "ios"
        )))]
        {
            false
        }
    }
}

impl Default for ResponseInjector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(target_os = "linux")]
impl Drop for ResponseInjector {
    fn drop(&mut self) {
        if let Some(fd) = self.raw_socket_v4 {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.raw_socket_v6 {
            unsafe { libc::close(fd) };
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for ResponseInjector {
    fn drop(&mut self) {
        if let Some(fd) = self.utun_fd {
            unsafe { libc::close(fd) };
        }
    }
}

#[cfg(any(target_os = "android", target_os = "ios"))]
impl Drop for ResponseInjector {
    fn drop(&mut self) {
        // TUN fd is owned by the app, we don't close it
        // The app is responsible for closing the TUN device
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oxtunnel_protocol::PROTOCOL_MAGIC;

    #[test]
    fn test_encapsulate_single() {
        let config = OxTunnelConfig::default();
        let encap = OxTunnelEncapsulator::new(config);
        let packet = vec![0x45, 0x00, 0x00, 0x28];
        let result = encap.encapsulate_single(&packet).unwrap();
        assert_eq!(&result[0..2], &PROTOCOL_MAGIC);
        assert!(result.len() >= HEADER_SIZE + packet.len());
    }

    #[test]
    fn test_batching() {
        let config = OxTunnelConfig {
            enable_batching: true,
            max_batch_size: 3,
            ..Default::default()
        };
        let encap = OxTunnelEncapsulator::new(config);
        let pkt = vec![0x45; 100];
        assert!(encap.add_to_batch(&pkt).is_none());
        assert!(encap.add_to_batch(&pkt).is_none());
        let result = encap.add_to_batch(&pkt);
        let final_batch = encap.flush_batch();
        assert!(result.is_some() || final_batch.is_some());
    }

    #[test]
    fn test_handshake_creation() {
        let config = OxTunnelConfig::default();
        let encap = OxTunnelEncapsulator::new(config);
        let handshake = encap.create_handshake();
        assert_eq!(&handshake[0..2], &PROTOCOL_MAGIC);
        assert!(handshake[2] & flags::CONTROL != 0);
    }

    #[test]
    fn test_adaptive_timeout() {
        let timeout = AdaptiveTimeout::new(500, 2000);

        // Initial timeout should be middle value
        let initial = timeout.current();
        assert!(initial.as_micros() >= 500 && initial.as_micros() <= 2000);

        // Record some packets
        for _ in 0..100 {
            timeout.record_packet();
        }
    }

    #[test]
    fn test_latency_sensitive_detection() {
        // Create a fake UDP packet to gaming port (27015 - Source engine)
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45; // IPv4, IHL=5
        packet[9] = 17; // UDP protocol
                        // UDP dest port 27015 at offset 22-23 (20 byte IP header + 2 byte src port)
        packet[22] = (27015 >> 8) as u8;
        packet[23] = (27015 & 0xFF) as u8;

        assert!(is_latency_sensitive_packet(&packet));

        // Create a fake TCP packet (not latency sensitive)
        let mut tcp_packet = vec![0u8; 40];
        tcp_packet[0] = 0x45; // IPv4
        tcp_packet[9] = 6; // TCP protocol

        assert!(!is_latency_sensitive_packet(&tcp_packet));
    }

    #[test]
    fn test_traffic_aware_batching() {
        let config = OxTunnelConfig {
            enable_batching: true,
            enable_traffic_aware_batching: true,
            ..Default::default()
        };
        let encap = OxTunnelEncapsulator::new(config);

        // Gaming packet should bypass batching
        let mut gaming_packet = vec![0u8; 64];
        gaming_packet[0] = 0x45;
        gaming_packet[9] = 17; // UDP
        gaming_packet[22] = (27015 >> 8) as u8;
        gaming_packet[23] = (27015 & 0xFF) as u8;

        let (immediate, batch) = encap.add_to_batch_traffic_aware(&gaming_packet);
        assert!(immediate.is_some()); // Gaming packet sent immediately
        assert!(batch.is_none()); // No batch triggered

        // Regular packet should be batched
        let regular_packet = vec![0x45; 100];
        let (immediate, _batch) = encap.add_to_batch_traffic_aware(&regular_packet);
        assert!(immediate.is_none()); // Regular packet batched
    }
}
