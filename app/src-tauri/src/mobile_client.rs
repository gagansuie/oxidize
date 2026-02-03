//! Mobile Client - Direct VPN connection without daemon
//!
//! On mobile platforms (Android/iOS), we don't use a daemon.
//! Instead, the app directly uses platform VPN APIs:
//! - Android: VpnService
//! - iOS: NEPacketTunnelProvider
//!
//! This module provides the client-side tunnel management.
//!
//! ## Smart Network Features
//! - **HandoffPredictor**: Predicts WiFi→LTE transitions 5+ seconds ahead
//! - **MptcpRedundancyScheduler**: Duplicates critical packets on multiple paths

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

#[cfg(any(target_os = "android", target_os = "ios"))]
use oxidize_common::oxtunnel_client::{CaptureConfig, PacketCaptureService, ResponseInjector};
#[cfg(any(target_os = "android", target_os = "ios"))]
use relay_client::client::{ClientConfig as OxTunnelClientConfig, TransportMode};
#[cfg(any(target_os = "android", target_os = "ios"))]
use relay_client::RelayClient;
#[cfg(any(target_os = "android", target_os = "ios"))]
use tokio::task::JoinHandle;

// Smart network handoff and redundancy
use oxidize_common::handoff_prediction::{HandoffPredictor, NetworkType};
use oxidize_common::mptcp_redundancy::{MptcpRedundancyScheduler, PacketImportance};

/// Mobile client configuration
#[derive(Debug, Clone)]
pub struct MobileClientConfig {
    /// Server address to connect to
    pub server_addr: SocketAddr,
    /// Enable encryption
    pub enable_encryption: bool,
    /// Enable compression
    pub enable_compression: bool,
    /// Enable proactive handoff prediction
    pub enable_handoff_prediction: bool,
    /// Enable multipath redundancy for critical traffic
    pub enable_redundancy: bool,
}

impl Default for MobileClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "0.0.0.0:51820".parse().unwrap(),
            enable_encryption: true,
            enable_compression: true,
            enable_handoff_prediction: true,
            enable_redundancy: true,
        }
    }
}

/// Mobile client statistics
#[derive(Debug, Default)]
pub struct MobileClientStats {
    pub packets_sent: AtomicU64,
    pub packets_received: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub connected_at: AtomicU64,
}

impl MobileClientStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn uptime_secs(&self) -> u64 {
        let connected_at = self.connected_at.load(Ordering::Relaxed);
        if connected_at == 0 {
            0
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now.saturating_sub(connected_at)
        }
    }
}

/// Mobile VPN client state
///
/// This manages the VPN tunnel on mobile platforms.
/// On Android, this works with VpnService.
/// On iOS, this works with NEPacketTunnelProvider.
///
/// ## Smart Network Features
/// - Predicts network handoffs (WiFi→LTE) 5+ seconds ahead
/// - Duplicates critical packets (gaming/VoIP) on multiple paths
/// - Triggers proactive FEC when signal quality degrades
pub struct MobileClientState {
    config: RwLock<Option<MobileClientConfig>>,
    connected: AtomicBool,
    stats: Arc<MobileClientStats>,
    server_id: RwLock<Option<String>>,

    // Smart network handoff prediction
    // Predicts WiFi→LTE transitions to trigger proactive FEC
    handoff_predictor: HandoffPredictor,

    // Multipath redundancy scheduler
    // Duplicates critical packets (gaming, VoIP) on backup paths
    redundancy_scheduler: MptcpRedundancyScheduler,

    #[cfg(any(target_os = "android", target_os = "ios"))]
    tun_fd: Mutex<Option<i32>>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    tunnel_task: Mutex<Option<JoinHandle<()>>>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    capture_service: Mutex<Option<Arc<PacketCaptureService>>>,
    #[cfg(any(target_os = "android", target_os = "ios"))]
    relay_client: Mutex<Option<Arc<RelayClient>>>,
}

impl MobileClientState {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(None),
            connected: AtomicBool::new(false),
            stats: Arc::new(MobileClientStats::new()),
            server_id: RwLock::new(None),
            handoff_predictor: HandoffPredictor::default(),
            redundancy_scheduler: MptcpRedundancyScheduler::default(),
            #[cfg(any(target_os = "android", target_os = "ios"))]
            tun_fd: Mutex::new(None),
            #[cfg(any(target_os = "android", target_os = "ios"))]
            tunnel_task: Mutex::new(None),
            #[cfg(any(target_os = "android", target_os = "ios"))]
            capture_service: Mutex::new(None),
            #[cfg(any(target_os = "android", target_os = "ios"))]
            relay_client: Mutex::new(None),
        }
    }

    /// Connect to VPN server
    ///
    /// On Android: This triggers VpnService.Builder to create tunnel
    /// On iOS: This triggers NEPacketTunnelProvider to start tunnel
    pub async fn connect(&self, server_id: String, server_addr: SocketAddr) -> Result<(), String> {
        if self.connected.load(Ordering::SeqCst) {
            return Err("Already connected".to_string());
        }

        let config = MobileClientConfig {
            server_addr,
            enable_encryption: true,
            enable_compression: true,
        };

        // Store config
        *self.config.write().await = Some(config);
        *self.server_id.write().await = Some(server_id);

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            if let Err(err) = self.start_tunnel(server_addr).await {
                *self.config.write().await = None;
                *self.server_id.write().await = None;
                return Err(err);
            }
        }

        // Mark connected time
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.stats.connected_at.store(now, Ordering::Relaxed);

        // Set connected flag
        self.connected.store(true, Ordering::SeqCst);

        tracing::info!("Mobile VPN connected to {}", server_addr);

        // Note: Actual VPN tunnel setup is platform-specific:
        // - Android: Handled by Kotlin/Java VpnService
        // - iOS: Handled by Swift NEPacketTunnelProvider
        // This Rust code provides the UDP transport layer

        Ok(())
    }

    /// Provide a TUN file descriptor from the platform VPN API
    #[cfg(any(target_os = "android", target_os = "ios"))]
    pub async fn set_tun_fd(&self, fd: i32) {
        let mut guard = self.tun_fd.lock().await;
        *guard = Some(fd);
        tracing::info!("Mobile tunnel fd set to {}", fd);
    }

    #[cfg(any(target_os = "android", target_os = "ios"))]
    async fn start_tunnel(&self, server_addr: SocketAddr) -> Result<(), String> {
        let config = self
            .config
            .read()
            .await
            .clone()
            .ok_or_else(|| "Missing mobile config".to_string())?;
        let tun_fd = {
            let guard = self.tun_fd.lock().await;
            (*guard).ok_or_else(|| "Mobile TUN fd not set".to_string())?
        };

        let capture_config = CaptureConfig {
            capture_tcp: true,
            capture_udp: true,
            capture_icmp: true,
            exclude_ips: vec![server_addr.ip()],
            tun_config: None,
            tun_fd: Some(tun_fd),
        };

        let capture_service = Arc::new(PacketCaptureService::new(capture_config));
        let (capture_rx, capture_handle) = capture_service.start();

        let mut response_injector = ResponseInjector::new();
        response_injector.set_tun_fd(tun_fd);
        let response_injector = Arc::new(response_injector);

        let client_config = OxTunnelClientConfig {
            server_addr,
            tcp_fallback_addr: Some(std::net::SocketAddr::new(server_addr.ip(), 51821)),
            transport_mode: TransportMode::Auto,
            enable_encryption: config.enable_encryption,
            encryption_key: None,
            enable_compression: config.enable_compression,
            compression_threshold: 512,
            enable_rohc: true,
            rohc_max_size: 1500,
            enable_ai_engine: true,
            keepalive_interval: Duration::from_secs(25),
            connection_timeout: Duration::from_secs(30),
            auth_config: None,
        };

        let client = RelayClient::new(client_config)
            .await
            .map_err(|e| format!("Failed to create relay client: {}", e))?;
        client
            .connect()
            .await
            .map_err(|e| format!("OxTunnel connect failed: {}", e))?;

        let client = Arc::new(client);
        let client_for_task = client.clone();
        let capture_clone = capture_service.clone();

        let task = tokio::spawn(async move {
            if let Err(err) = client_for_task
                .run_with_injection(capture_rx, response_injector)
                .await
            {
                tracing::error!("Mobile client error: {}", err);
            }
            capture_clone.stop();
            let _ = capture_handle.await;
        });

        *self.relay_client.lock().await = Some(client);
        *self.capture_service.lock().await = Some(capture_service);
        *self.tunnel_task.lock().await = Some(task);

        Ok(())
    }

    /// Disconnect from VPN
    pub async fn disconnect(&self) -> Result<(), String> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err("Not connected".to_string());
        }

        #[cfg(any(target_os = "android", target_os = "ios"))]
        {
            if let Some(client) = self.relay_client.lock().await.take() {
                client.disconnect().await;
            }
            if let Some(capture_service) = self.capture_service.lock().await.take() {
                capture_service.stop();
            }
            if let Some(task) = self.tunnel_task.lock().await.take() {
                task.abort();
            }
        }

        self.connected.store(false, Ordering::SeqCst);
        *self.config.write().await = None;
        *self.server_id.write().await = None;

        // Reset stats
        self.stats.connected_at.store(0, Ordering::Relaxed);

        tracing::info!("Mobile VPN disconnected");
        Ok(())
    }

    /// Check if connected
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::SeqCst)
    }

    /// Get connection stats
    pub fn get_stats(&self) -> MobileConnectionStats {
        MobileConnectionStats {
            connected: self.is_connected(),
            uptime_secs: self.stats.uptime_secs(),
            bytes_sent: self.stats.bytes_sent.load(Ordering::Relaxed),
            bytes_received: self.stats.bytes_received.load(Ordering::Relaxed),
            packets_sent: self.stats.packets_sent.load(Ordering::Relaxed),
            packets_received: self.stats.packets_received.load(Ordering::Relaxed),
        }
    }

    /// Get server ID
    pub async fn server_id(&self) -> Option<String> {
        self.server_id.read().await.clone()
    }

    // ========================================================================
    // Smart Network Handoff Prediction
    // ========================================================================

    /// Update WiFi signal strength
    /// Called from platform layer when signal changes
    ///
    /// # Arguments
    /// * `rssi` - WiFi RSSI in dBm (typically -30 to -90)
    /// * `rtt_us` - Round-trip time in microseconds
    pub fn update_wifi_signal(&self, rssi: i8, rtt_us: u32) {
        self.handoff_predictor.update_wifi(rssi, rtt_us);

        // Check if we should prepare for handoff
        if let Some(prediction) = self.check_handoff_prediction() {
            tracing::info!(
                "Handoff predicted: probability={}%, preparing backup path",
                prediction.probability
            );
        }
    }

    /// Update LTE/5G signal strength
    /// Called from platform layer when cellular signal changes
    ///
    /// # Arguments
    /// * `rsrp` - LTE RSRP in dBm (typically -44 to -140)
    pub fn update_cellular_signal(&self, rsrp: i8) {
        self.handoff_predictor.update_lte(rsrp);
    }

    /// Check if a network handoff is predicted
    /// Returns handoff info if probability > 50%
    pub fn check_handoff_prediction(&self) -> Option<HandoffPrediction> {
        let probability = self.handoff_predictor.handoff_probability();

        if probability > 50 {
            Some(HandoffPrediction {
                probability,
                current_network: self.handoff_predictor.current_network(),
                should_enable_fec: probability > 70,
                should_prepare_backup: probability > 60,
            })
        } else {
            None
        }
    }

    /// Get handoff prediction statistics
    pub fn handoff_stats(&self) -> HandoffStats {
        let stats = &self.handoff_predictor.stats;
        HandoffStats {
            predictions_made: stats.predictions_made.load(Ordering::Relaxed),
            handoffs_predicted: stats.handoffs_predicted.load(Ordering::Relaxed),
            handoffs_actual: stats.handoffs_actual.load(Ordering::Relaxed),
            correct_predictions: stats.correct_predictions.load(Ordering::Relaxed),
        }
    }

    // ========================================================================
    // Multipath Redundancy for Critical Traffic
    // ========================================================================

    /// Register a network path for redundancy
    ///
    /// # Arguments
    /// * `path_id` - Unique path identifier
    /// * `rtt_ms` - Path RTT in milliseconds
    /// * `loss_rate` - Packet loss rate (0.0 - 1.0)
    /// * `is_primary` - Whether this is the primary path
    pub fn register_path(&self, path_id: u32, rtt_ms: f32, loss_rate: f32, is_primary: bool) {
        self.redundancy_scheduler
            .update_path(path_id, rtt_ms, loss_rate, is_primary);
        tracing::debug!(
            "Registered path {}: RTT={}ms, loss={:.2}%, primary={}",
            path_id,
            rtt_ms,
            loss_rate * 100.0,
            is_primary
        );
    }

    /// Determine packet importance for redundancy decisions
    ///
    /// # Arguments
    /// * `dst_port` - Destination port of the packet
    /// * `protocol` - IP protocol number (6=TCP, 17=UDP)
    pub fn classify_packet_importance(&self, dst_port: u16, protocol: u8) -> PacketImportance {
        match (protocol, dst_port) {
            // Gaming/VoIP - always duplicate
            (17, 3478..=3479) => PacketImportance::Critical, // STUN/TURN
            (17, 5060..=5061) => PacketImportance::Critical, // SIP
            (17, 16384..=32767) => PacketImportance::Critical, // RTP range

            // Real-time apps - duplicate on quality difference
            (17, 443) => PacketImportance::High,   // QUIC
            (17, 51820) => PacketImportance::High, // OxTunnel

            // Interactive - best path only
            (6, 22) => PacketImportance::Normal,  // SSH
            (6, 443) => PacketImportance::Normal, // HTTPS

            // Bulk transfer - can be delayed
            (6, 80) => PacketImportance::Low, // HTTP
            (6, 21) => PacketImportance::Low, // FTP

            _ => PacketImportance::Normal,
        }
    }

    /// Check if packet should be sent on redundant path
    ///
    /// # Arguments
    /// * `importance` - Packet importance level
    /// * `sequence` - Packet sequence number
    pub fn should_send_redundant(&self, importance: PacketImportance, sequence: u64) -> bool {
        self.redundancy_scheduler
            .should_duplicate(importance, sequence)
    }

    /// Get redundancy statistics
    pub fn redundancy_stats(&self) -> RedundancyStats {
        let stats = &self.redundancy_scheduler.stats;
        RedundancyStats {
            packets_sent_primary: stats.packets_sent_primary.load(Ordering::Relaxed),
            packets_sent_backup: stats.packets_sent_backup.load(Ordering::Relaxed),
            redundant_packets_sent: stats.redundant_packets_sent.load(Ordering::Relaxed),
            redundant_packets_useful: stats.redundant_packets_useful.load(Ordering::Relaxed),
            failovers: stats.failovers.load(Ordering::Relaxed),
        }
    }
}

impl Default for MobileClientState {
    fn default() -> Self {
        Self::new()
    }
}

/// Mobile connection statistics for UI
#[derive(Debug, Clone, serde::Serialize)]
pub struct MobileConnectionStats {
    pub connected: bool,
    pub uptime_secs: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

/// Handoff prediction result
#[derive(Debug, Clone, serde::Serialize)]
pub struct HandoffPrediction {
    /// Probability of handoff (0-100%)
    pub probability: u32,
    /// Current network type
    pub current_network: NetworkType,
    /// Should enable proactive FEC
    pub should_enable_fec: bool,
    /// Should prepare backup path
    pub should_prepare_backup: bool,
}

/// Handoff prediction statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct HandoffStats {
    pub predictions_made: u64,
    pub handoffs_predicted: u64,
    pub handoffs_actual: u64,
    pub correct_predictions: u64,
}

/// Multipath redundancy statistics
#[derive(Debug, Clone, serde::Serialize)]
pub struct RedundancyStats {
    pub packets_sent_primary: u64,
    pub packets_sent_backup: u64,
    pub redundant_packets_sent: u64,
    pub redundant_packets_useful: u64,
    pub failovers: u64,
}

// ============================================================================
// Android-specific VPN integration
// ============================================================================

/// Android VPN configuration for VpnService.Builder
#[cfg(target_os = "android")]
#[derive(Debug, Clone, serde::Serialize)]
pub struct AndroidVpnConfig {
    /// TUN interface address (assigned by server)
    pub tun_address: String,
    /// TUN interface netmask
    pub tun_netmask: String,
    /// DNS servers
    pub dns_servers: Vec<String>,
    /// Routes to tunnel (empty = all traffic)
    pub routes: Vec<String>,
    /// MTU size
    pub mtu: u32,
}

#[cfg(target_os = "android")]
impl Default for AndroidVpnConfig {
    fn default() -> Self {
        Self {
            tun_address: "10.0.0.2".to_string(),
            tun_netmask: "255.255.255.0".to_string(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            routes: vec!["0.0.0.0/0".to_string()], // All traffic
            mtu: 1400,
        }
    }
}

// ============================================================================
// iOS-specific VPN integration
// ============================================================================

/// iOS VPN configuration for NEPacketTunnelProvider
#[cfg(target_os = "ios")]
#[derive(Debug, Clone, serde::Serialize)]
pub struct IosVpnConfig {
    /// Tunnel remote address
    pub tunnel_remote_address: String,
    /// IPv4 settings
    pub ipv4_address: String,
    pub ipv4_netmask: String,
    /// DNS settings
    pub dns_servers: Vec<String>,
    /// MTU
    pub mtu: u32,
}

#[cfg(target_os = "ios")]
impl Default for IosVpnConfig {
    fn default() -> Self {
        Self {
            tunnel_remote_address: "10.0.0.1".to_string(),
            ipv4_address: "10.0.0.2".to_string(),
            ipv4_netmask: "255.255.255.0".to_string(),
            dns_servers: vec!["1.1.1.1".to_string()],
            mtu: 1400,
        }
    }
}
