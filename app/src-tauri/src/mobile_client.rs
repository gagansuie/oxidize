//! Mobile Client - Direct VPN connection without daemon
//!
//! On mobile platforms (Android/iOS), we don't use a daemon.
//! Instead, the app directly uses platform VPN APIs:
//! - Android: VpnService
//! - iOS: NEPacketTunnelProvider
//!
//! This module provides the client-side tunnel management.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mobile client configuration
#[derive(Debug, Clone)]
pub struct MobileClientConfig {
    /// Server address to connect to
    pub server_addr: SocketAddr,
    /// Enable encryption
    pub enable_encryption: bool,
    /// Enable compression
    pub enable_compression: bool,
}

impl Default for MobileClientConfig {
    fn default() -> Self {
        Self {
            server_addr: "0.0.0.0:4433".parse().unwrap(),
            enable_encryption: true,
            enable_compression: true,
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
pub struct MobileClientState {
    config: RwLock<Option<MobileClientConfig>>,
    connected: AtomicBool,
    stats: Arc<MobileClientStats>,
    server_id: RwLock<Option<String>>,
}

impl MobileClientState {
    pub fn new() -> Self {
        Self {
            config: RwLock::new(None),
            connected: AtomicBool::new(false),
            stats: Arc::new(MobileClientStats::new()),
            server_id: RwLock::new(None),
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

    /// Disconnect from VPN
    pub async fn disconnect(&self) -> Result<(), String> {
        if !self.connected.load(Ordering::SeqCst) {
            return Err("Not connected".to_string());
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
