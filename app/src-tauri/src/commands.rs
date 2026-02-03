use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs};
use tauri::Manager;
use tokio::sync::Mutex;

const API_BASE_URL: &str = "https://oxd.sh";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub connected: bool,
    pub server: Option<String>,
    pub ip: Option<String>,
    pub original_ip: Option<String>,
    pub uptime_secs: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub compression_saved: u64,
    pub latency_ms: Option<u32>,
    // ML metrics from backend
    pub fec_recovered: u64,
    pub fec_sent: u64,
    pub loss_predictions: u64,
    pub congestion_adjustments: u64,
    pub path_switches: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Region {
    pub id: String,           // Region code (e.g., 'ord')
    pub name: String,         // Region group (e.g., 'North America')
    pub location: String,     // City (e.g., 'Chicago, Illinois')
    pub country_code: String, // ISO country code for flag
    pub status: String,       // online, maintenance, offline
    pub latency_ms: Option<u32>,
    pub load: u8,
    pub server_count: u32,
    pub server_ids: Vec<String>, // Best server first
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct ApiRegion {
    id: String,
    name: String,
    location: String,
    country_code: String,
    status: String,
    #[serde(default)]
    latency: Option<String>,
    load: u8,
    server_count: u32,
    server_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    /// Auto-connect on launch
    pub auto_connect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthCredentials {
    pub api_key: String,
    pub api_secret: String,
}

#[derive(Default)]
pub struct AppState {
    pub config: Mutex<AppConfig>,
    pub original_ip: Mutex<Option<String>>,
    pub cached_relay_latency: Mutex<Option<u32>>,
    pub last_latency_check: Mutex<Option<std::time::Instant>>,
    /// Cached server data: server_id -> ipv4 address
    pub server_ips: Mutex<std::collections::HashMap<String, String>>,
    /// Cached server data: server_id -> ipv6 address
    pub server_ipv6s: Mutex<std::collections::HashMap<String, String>>,
    /// Round-robin index per region: region_id -> last used index
    pub region_server_index: Mutex<std::collections::HashMap<String, usize>>,
    /// Cached region server lists: region_id -> Vec<server_id>
    pub region_servers: Mutex<std::collections::HashMap<String, Vec<String>>>,
    /// Device authentication credentials (fetched from API)
    pub auth_credentials: Mutex<Option<DeviceAuthCredentials>>,
}

const METRICS_PORT: u16 = 9090; // TCP port for latency measurement

#[tauri::command]
pub async fn connect(
    server_id: String,
    app: tauri::AppHandle,
    state: tauri::State<'_, AppState>,
) -> Result<ConnectionStatus, String> {
    tracing::info!("Connecting to relay via server: {}", server_id);

    // Daemon is required for full traffic tunneling and IP protection
    // Auto-install if not running (handles macOS DMG, AppImage, and fresh installs)
    if !is_daemon_running().await {
        tracing::info!("Daemon not running, attempting auto-install...");
        match install_daemon(app.clone()).await {
            Ok(msg) => {
                tracing::info!("Daemon installed: {}", msg);
                // Give daemon time to start
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

                // Verify it's now running
                if !is_daemon_running().await {
                    return Err(
                        "Daemon installed but failed to start. Please check system logs or try restarting the app."
                            .to_string(),
                    );
                }
            }
            Err(e) => {
                return Err(format!(
                    "Failed to install daemon: {}. You may need to manually install via Settings → Install Daemon.",
                    e
                ));
            }
        }
    }

    // Check if already connected
    if let Ok(status) = daemon_get_status().await {
        if status
            .get("connected")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Err("Already connected. Disconnect first.".to_string());
        }
    }

    // Capture original IP BEFORE connecting (for IP protection proof)
    let original_ip = get_external_ip().await.ok();
    {
        let mut orig_ip = state.original_ip.lock().await;
        *orig_ip = original_ip.clone();
    }

    // Look up server IP from cache (populated by get_regions)
    let server_address = {
        let ips = state.server_ips.lock().await;
        ips.get(&server_id).cloned()
    };

    let server_address = server_address.ok_or_else(|| {
        format!(
            "Server {} not found. Please refresh server list.",
            server_id
        )
    })?;

    tracing::info!("Connecting via daemon to {}:{}", server_address, 51820);
    daemon_connect(server_id.clone(), server_address.clone()).await?;

    crate::set_connected(true);

    // Use the server address we connected to
    let server_ip = get_server_ip(&server_address).await.ok();

    // Measure latency through relay
    let relay_latency = ping_relay(&server_address).await.ok();

    Ok(ConnectionStatus {
        connected: true,
        server: Some(server_id),
        ip: server_ip,
        original_ip,
        uptime_secs: 0,
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
        compression_saved: 0,
        latency_ms: relay_latency,
        fec_recovered: 0,
        fec_sent: 0,
        loss_predictions: 0,
        congestion_adjustments: 0,
        path_switches: 0,
    })
}

#[tauri::command]
pub async fn disconnect() -> Result<ConnectionStatus, String> {
    tracing::info!("Disconnecting...");

    if !is_daemon_running().await {
        crate::set_connected(false);
        return Ok(ConnectionStatus {
            connected: false,
            server: None,
            ip: None,
            original_ip: None,
            uptime_secs: 0,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            compression_saved: 0,
            latency_ms: None,
            fec_recovered: 0,
            fec_sent: 0,
            loss_predictions: 0,
            congestion_adjustments: 0,
            path_switches: 0,
        });
    }

    let response = send_daemon_command(r#"{"type":"Disconnect"}"#).await?;
    let bytes_sent = response["data"]["bytes_sent"].as_u64().unwrap_or(0);
    let bytes_received = response["data"]["bytes_received"].as_u64().unwrap_or(0);
    let uptime_secs = response["data"]["uptime_secs"].as_u64().unwrap_or(0);
    let packets_sent = response["data"]["packets_sent"].as_u64().unwrap_or(0);
    let packets_received = response["data"]["packets_received"].as_u64().unwrap_or(0);
    let compression_saved = response["data"]["compression_saved"].as_u64().unwrap_or(0);

    crate::set_connected(false);
    tracing::info!(
        "Disconnected. Sent: {} bytes, Received: {} bytes, Compression saved: {} bytes",
        bytes_sent,
        bytes_received,
        compression_saved
    );

    Ok(ConnectionStatus {
        connected: false,
        server: None,
        ip: None,
        original_ip: None,
        uptime_secs,
        bytes_sent,
        bytes_received,
        packets_sent,
        packets_received,
        compression_saved,
        latency_ms: None,
        fec_recovered: response["data"]["fec_recovered"].as_u64().unwrap_or(0),
        fec_sent: response["data"]["fec_sent"].as_u64().unwrap_or(0),
        loss_predictions: response["data"]["loss_predictions"].as_u64().unwrap_or(0),
        congestion_adjustments: response["data"]["congestion_adjustments"]
            .as_u64()
            .unwrap_or(0),
        path_switches: response["data"]["path_switches"].as_u64().unwrap_or(0),
    })
}

#[tauri::command]
pub async fn get_status(state: tauri::State<'_, AppState>) -> Result<ConnectionStatus, String> {
    // Check daemon status
    if !is_daemon_running().await {
        return Ok(ConnectionStatus {
            connected: false,
            server: None,
            ip: None,
            original_ip: None,
            uptime_secs: 0,
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            compression_saved: 0,
            latency_ms: None,
            fec_recovered: 0,
            fec_sent: 0,
            loss_predictions: 0,
            congestion_adjustments: 0,
            path_switches: 0,
        });
    }

    let data = daemon_get_status().await?;
    let connected = data
        .get("connected")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Get stored original IP from state
    let original_ip = state.original_ip.lock().await.clone();

    // Get server address from daemon status (format: "ip:port")
    let server_addr_str = data
        .get("server_addr")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // Extract just the IP part
    let server_ip_only = server_addr_str.split(':').next().unwrap_or("").to_string();

    if connected {
        // Use server IP from daemon status
        let server_ip = if server_ip_only.is_empty() {
            None
        } else {
            Some(server_ip_only.clone())
        };

        // Use cached latency, refresh every 5 seconds OR if cache is empty
        let relay_latency = {
            let last_check = *state.last_latency_check.lock().await;
            let cached = *state.cached_relay_latency.lock().await;

            // Force refresh if cache is empty or every 5 seconds
            let should_refresh = cached.is_none()
                || match last_check {
                    Some(t) => t.elapsed().as_secs() >= 5,
                    None => true,
                };

            if should_refresh && !server_ip_only.is_empty() {
                // Try to get latency with reasonable timeout
                match tokio::time::timeout(
                    std::time::Duration::from_millis(1500),
                    ping_relay(&server_ip_only),
                )
                .await
                {
                    Ok(Ok(l)) => {
                        let mut cached_mut = state.cached_relay_latency.lock().await;
                        let mut last_check_mut = state.last_latency_check.lock().await;
                        *cached_mut = Some(l);
                        *last_check_mut = Some(std::time::Instant::now());
                        tracing::debug!("Relay latency measured: {}ms", l);
                        Some(l)
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("Relay ping failed: {}", e);
                        cached // Return cached value if available
                    }
                    Err(_) => {
                        tracing::warn!("Relay ping timed out");
                        cached // Return cached value if available
                    }
                }
            } else {
                cached
            }
        };

        return Ok(ConnectionStatus {
            connected: true,
            server: data
                .get("server_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            ip: server_ip,
            original_ip,
            uptime_secs: data
                .get("uptime_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            bytes_sent: data.get("bytes_sent").and_then(|v| v.as_u64()).unwrap_or(0),
            bytes_received: data
                .get("bytes_received")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            packets_sent: data
                .get("packets_sent")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            packets_received: data
                .get("packets_received")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            compression_saved: data
                .get("compression_saved")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            // Prefer UDP tunnel latency when available, fall back to TCP ping
            latency_ms: {
                let tunnel_latency_us = data
                    .get("tunnel_latency_us")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if tunnel_latency_us > 0 {
                    Some((tunnel_latency_us / 1000) as u32) // Convert us to ms
                } else {
                    relay_latency // Fall back to TCP-based measurement
                }
            },
            fec_recovered: data
                .get("fec_recovered")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            fec_sent: data.get("fec_sent").and_then(|v| v.as_u64()).unwrap_or(0),
            loss_predictions: data
                .get("loss_predictions")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            congestion_adjustments: data
                .get("congestion_adjustments")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            path_switches: data
                .get("path_switches")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
        });
    }

    Ok(ConnectionStatus {
        connected: false,
        server: None,
        ip: None,
        original_ip: None,
        uptime_secs: 0,
        bytes_sent: 0,
        bytes_received: 0,
        packets_sent: 0,
        packets_received: 0,
        compression_saved: 0,
        latency_ms: None,
        fec_recovered: 0,
        fec_sent: 0,
        loss_predictions: 0,
        congestion_adjustments: 0,
        path_switches: 0,
    })
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct ApiServer {
    id: String,
    #[serde(default)]
    ipv4: Option<String>,
    #[serde(default)]
    ipv6: Option<String>,
    #[serde(default)]
    region: String,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct RegionsResponse {
    regions: Vec<ApiRegion>,
    #[serde(default)]
    servers: Vec<ApiServer>,
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    error: Option<String>,
}

/// OxTunnel ping magic bytes
const PING_MAGIC: [u8; 4] = [0x4F, 0x58, 0x50, 0x49]; // "OXPI"
const PONG_MAGIC: [u8; 4] = [0x4F, 0x58, 0x50, 0x4F]; // "OXPO"

/// Ping a server using UDP (preferred) with TCP fallback
/// Tries IPv6 first if available, then IPv4
async fn ping_server(ipv4: Option<&str>, ipv6: Option<&str>) -> Option<u32> {
    // Try UDP ping first (more accurate for tunnel latency)
    // Prefer IPv6 over IPv4
    if let Some(ip6) = ipv6 {
        let addr = format!("[{}]:51820", ip6);
        if let Some(latency) = ping_udp(&addr).await {
            tracing::debug!("UDP ping to {} succeeded: {}ms", addr, latency);
            return Some(latency);
        }
        tracing::debug!("UDP ping to {} failed, trying next", addr);
    }

    if let Some(ip4) = ipv4 {
        let addr = format!("{}:51820", ip4);
        if let Some(latency) = ping_udp(&addr).await {
            tracing::debug!("UDP ping to {} succeeded: {}ms", addr, latency);
            return Some(latency);
        }
        tracing::debug!("UDP ping to {} failed, trying TCP fallback", addr);
    }

    // Fall back to TCP ping if UDP fails
    if let Some(ip6) = ipv6 {
        let addr = format!("[{}]:9090", ip6);
        if let Some(latency) = ping_tcp(&addr).await {
            tracing::debug!("TCP ping to {} succeeded: {}ms", addr, latency);
            return Some(latency);
        }
        tracing::debug!("TCP ping to {} failed", addr);
    }

    if let Some(ip4) = ipv4 {
        let addr = format!("{}:9090", ip4);
        if let Some(latency) = ping_tcp(&addr).await {
            tracing::debug!("TCP ping to {} succeeded: {}ms", addr, latency);
            return Some(latency);
        }
        tracing::debug!("TCP ping to {} failed", addr);
    }

    tracing::warn!("All ping attempts failed for v4={:?} v6={:?}", ipv4, ipv6);
    None
}

/// UDP ping using OxTunnel PING/PONG protocol
async fn ping_udp(addr: &str) -> Option<u32> {
    use std::time::Instant;
    use tokio::net::UdpSocket;

    let socket = match UdpSocket::bind("[::]:0").await {
        Ok(s) => s,
        Err(_) => match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return None,
        },
    };

    // Send PING packet with timestamp for verification
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let mut ping_packet = [0u8; 12];
    ping_packet[..4].copy_from_slice(&PING_MAGIC);
    ping_packet[4..12].copy_from_slice(&timestamp.to_le_bytes());

    let start = Instant::now();

    if socket.send_to(&ping_packet, addr).await.is_err() {
        return None;
    }

    let mut buf = [0u8; 64];
    match tokio::time::timeout(
        std::time::Duration::from_millis(500),
        socket.recv_from(&mut buf),
    )
    .await
    {
        Ok(Ok((len, _))) if len >= 4 && buf[..4] == PONG_MAGIC => {
            // Use microseconds for precision, minimum 1ms
            let micros = start.elapsed().as_micros();
            Some(std::cmp::max(1, (micros / 1000) as u32))
        }
        _ => None,
    }
}

/// TCP ping (fallback) - measures connection establishment time
async fn ping_tcp(addr: &str) -> Option<u32> {
    use std::time::Instant;
    use tokio::net::TcpStream;

    let start = Instant::now();

    match tokio::time::timeout(
        std::time::Duration::from_millis(1000),
        TcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_)) => {
            // Use microseconds for precision, minimum 1ms
            let micros = start.elapsed().as_micros();
            Some(std::cmp::max(1, (micros / 1000) as u32))
        }
        Ok(Err(_)) => {
            // Connection refused but we got a response = valid RTT
            let micros = start.elapsed().as_micros();
            let elapsed = (micros / 1000) as u32;
            if elapsed < 500 {
                Some(std::cmp::max(1, elapsed))
            } else {
                None
            }
        }
        Err(_) => None, // Timeout
    }
}

/// Legacy ping function for backward compatibility
#[allow(dead_code)]
async fn ping_ip(ip: &str) -> Option<u32> {
    ping_server(Some(ip), None).await
}

#[tauri::command]
pub async fn get_regions(state: tauri::State<'_, AppState>) -> Result<Vec<Region>, String> {
    let url = format!("{}/api/servers", API_BASE_URL);
    tracing::info!("Fetching regions from: {}", url);

    let response = reqwest::Client::new()
        .get(&url)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch regions: {}", e);
            format!("Failed to fetch regions: {}", e)
        })?;

    tracing::info!("API response status: {}", response.status());

    if !response.status().is_success() {
        return Err(format!("API returned status: {}", response.status()));
    }

    let text = response
        .text()
        .await
        .map_err(|e| format!("Failed to read response: {}", e))?;
    tracing::info!("API response length: {} bytes", text.len());

    let api_response: RegionsResponse =
        serde_json::from_str(&text).map_err(|e| format!("Failed to parse response: {}", e))?;

    if let Some(error) = api_response.error {
        return Err(format!("API error: {}", error));
    }

    // Build maps of server_id -> ipv4/ipv6 for latency measurement and connection
    let server_ips: std::collections::HashMap<String, String> = api_response
        .servers
        .iter()
        .filter_map(|s| s.ipv4.as_ref().map(|ip| (s.id.clone(), ip.clone())))
        .collect();

    let server_ipv6s: std::collections::HashMap<String, String> = api_response
        .servers
        .iter()
        .filter_map(|s| s.ipv6.as_ref().map(|ip| (s.id.clone(), ip.clone())))
        .collect();

    // Cache server IPs for use when connecting (prefer IPv6 when available)
    {
        let mut cached_ips = state.server_ips.lock().await;
        *cached_ips = server_ips.clone();
        let mut cached_ipv6s = state.server_ipv6s.lock().await;
        *cached_ipv6s = server_ipv6s.clone();
        tracing::info!(
            "Cached {} IPv4 and {} IPv6 server addresses",
            cached_ips.len(),
            cached_ipv6s.len()
        );
    }

    // Measure latency to each server using UDP (IPv6 preferred) with TCP fallback
    // Build list of (server_id, ipv4, ipv6) tuples
    let server_addrs: Vec<(String, Option<String>, Option<String>)> = api_response
        .servers
        .iter()
        .map(|s| (s.id.clone(), s.ipv4.clone(), s.ipv6.clone()))
        .collect();

    tracing::info!(
        "Measuring latency to {} servers (UDP IPv6 preferred, TCP fallback)",
        server_addrs.len()
    );

    let latency_futures: Vec<_> = server_addrs
        .iter()
        .map(|(id, ipv4, ipv6)| {
            let id = id.clone();
            let ipv4 = ipv4.clone();
            let ipv6 = ipv6.clone();
            async move {
                let result = ping_server(ipv4.as_deref(), ipv6.as_deref()).await;
                tracing::info!(
                    "Ping {} (v4: {:?}, v6: {:?}) -> {:?}ms",
                    id,
                    ipv4,
                    ipv6,
                    result
                );
                (id, result)
            }
        })
        .collect();

    let latency_results: std::collections::HashMap<String, Option<u32>> =
        futures::future::join_all(latency_futures)
            .await
            .into_iter()
            .collect();

    tracing::info!("Latency measurement complete (UDP/IPv6 preferred)");

    // Build regions with measured latency
    let mut regions: Vec<Region> = api_response
        .regions
        .into_iter()
        .filter(|r| r.status == "online" || r.status == "maintenance")
        .map(|r| {
            // Find best (lowest) latency among servers in this region
            let best_latency = r
                .server_ids
                .iter()
                .filter_map(|sid| latency_results.get(sid).copied().flatten())
                .min();

            Region {
                id: r.id,
                name: r.name,
                location: r.location,
                country_code: r.country_code,
                status: r.status,
                latency_ms: best_latency,
                load: r.load,
                server_count: r.server_count,
                server_ids: r.server_ids,
            }
        })
        .collect();

    // Sort by latency (lowest first), None values last
    regions.sort_by(|a, b| match (a.latency_ms, b.latency_ms) {
        (Some(a_lat), Some(b_lat)) => a_lat.cmp(&b_lat),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    });

    // Cache region -> server_ids mapping for round-robin
    {
        let mut region_servers = state.region_servers.lock().await;
        for r in &regions {
            region_servers.insert(r.id.clone(), r.server_ids.clone());
        }
        tracing::info!("Cached {} region server mappings", region_servers.len());
    }

    tracing::info!("Fetched {} regions, measured latencies", regions.len());
    Ok(regions)
}

/// Get next server for a region using round-robin selection
#[tauri::command]
pub async fn get_next_server_for_region(
    region_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<String, String> {
    let region_servers = state.region_servers.lock().await;
    let server_ids = region_servers
        .get(&region_id)
        .ok_or_else(|| format!("Region {} not found", region_id))?;

    if server_ids.is_empty() {
        return Err(format!("No servers in region {}", region_id));
    }

    // Get and increment round-robin index
    let mut indices = state.region_server_index.lock().await;
    let current_index = indices.get(&region_id).copied().unwrap_or(0);
    let next_index = (current_index + 1) % server_ids.len();
    indices.insert(region_id.clone(), next_index);

    let server_id = server_ids[current_index].clone();
    tracing::info!(
        "Round-robin: region {} -> server {} (index {}/{})",
        region_id,
        server_id,
        current_index + 1,
        server_ids.len()
    );

    Ok(server_id)
}

#[derive(Debug, Clone, Deserialize)]
struct GeoLocation {
    #[serde(default)]
    lat: f64,
    #[serde(default)]
    lon: f64,
    #[serde(default)]
    country_code: String,
}

// Region coordinates (approximate city centers)
fn get_region_coords(region_id: &str) -> Option<(f64, f64)> {
    match region_id {
        "ord" => Some((41.8781, -87.6298)),  // Chicago
        "iad" => Some((38.9072, -77.0369)),  // Washington DC / Ashburn
        "sjc" => Some((37.3382, -121.8863)), // San Jose
        "lax" => Some((34.0522, -118.2437)), // Los Angeles
        "dfw" => Some((32.7767, -96.7970)),  // Dallas
        "sea" => Some((47.6062, -122.3321)), // Seattle
        "ewr" => Some((40.7128, -74.0060)),  // Newark/NYC
        "mia" => Some((25.7617, -80.1918)),  // Miami
        "atl" => Some((33.7490, -84.3880)),  // Atlanta
        "den" => Some((39.7392, -104.9903)), // Denver
        "phx" => Some((33.4484, -112.0740)), // Phoenix
        "ams" => Some((52.3676, 4.9041)),    // Amsterdam
        "lhr" => Some((51.5074, -0.1278)),   // London
        "fra" => Some((50.1109, 8.6821)),    // Frankfurt
        "cdg" => Some((48.8566, 2.3522)),    // Paris
        "mad" => Some((40.4168, -3.7038)),   // Madrid
        "waw" => Some((52.2297, 21.0122)),   // Warsaw
        "sin" => Some((1.3521, 103.8198)),   // Singapore
        "nrt" => Some((35.6762, 139.6503)),  // Tokyo
        "hkg" => Some((22.3193, 114.1694)),  // Hong Kong
        "syd" => Some((-33.8688, 151.2093)), // Sydney
        "gru" => Some((-23.5505, -46.6333)), // São Paulo
        "bom" => Some((19.0760, 72.8777)),   // Mumbai
        "jnb" => Some((-26.2041, 28.0473)),  // Johannesburg
        _ => None,
    }
}

fn haversine_distance(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = 6371.0; // Earth's radius in km
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (dlon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().asin();
    r * c
}

/// Get the closest region based on user's IP geolocation
#[tauri::command]
pub async fn get_closest_region(state: tauri::State<'_, AppState>) -> Result<Region, String> {
    // Get user's location via IP geolocation
    let geo_url = "http://ip-api.com/json/?fields=lat,lon,countryCode";
    let geo: GeoLocation = reqwest::get(geo_url)
        .await
        .map_err(|e| format!("Failed to get location: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse location: {}", e))?;

    tracing::info!(
        "User location: lat={}, lon={}, country={}",
        geo.lat,
        geo.lon,
        geo.country_code
    );

    // Get all regions
    let regions = get_regions(state).await?;

    if regions.is_empty() {
        return Err("No regions available".to_string());
    }

    // Find closest region by distance
    let closest = regions
        .into_iter()
        .filter(|r| r.status == "online")
        .min_by(|a, b| {
            let dist_a = get_region_coords(&a.id)
                .map(|(lat, lon)| haversine_distance(geo.lat, geo.lon, lat, lon))
                .unwrap_or(f64::MAX);
            let dist_b = get_region_coords(&b.id)
                .map(|(lat, lon)| haversine_distance(geo.lat, geo.lon, lat, lon))
                .unwrap_or(f64::MAX);
            dist_a
                .partial_cmp(&dist_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .ok_or_else(|| "No online regions found".to_string())?;

    tracing::info!("Closest region: {} ({})", closest.id, closest.location);
    Ok(closest)
}

#[tauri::command]
pub async fn get_config(state: tauri::State<'_, AppState>) -> Result<AppConfig, String> {
    let config = state.config.lock().await;
    Ok(config.clone())
}

#[tauri::command]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// Ping relay by measuring TCP connect time to metrics port (reliable method)
#[tauri::command]
pub async fn ping_relay(server_ip: &str) -> Result<u32, String> {
    use std::time::Instant;
    use tokio::net::TcpStream;

    // Use provided server IP with METRICS_PORT (TCP)
    let server_addr: SocketAddr = format!("{}:{}", server_ip, METRICS_PORT)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve: {}", e))?
        .next()
        .ok_or_else(|| "No address found".to_string())?;

    let start = Instant::now();

    // Try TCP connect - even if it fails/resets, we get RTT measurement
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(2000),
        TcpStream::connect(server_addr),
    )
    .await;

    match result {
        Ok(Ok(_)) => {
            // Connection succeeded
            let latency = start.elapsed().as_millis() as u32;
            Ok(latency.max(1))
        }
        Ok(Err(_)) => {
            // Connection refused/reset - but we still got a response, so RTT is valid
            let latency = start.elapsed().as_millis() as u32;
            if latency < 1000 {
                // Got a quick rejection = we have RTT
                Ok(latency.max(1))
            } else {
                Err("Connection failed".to_string())
            }
        }
        Err(_) => Err("Timeout".to_string()),
    }
}

#[tauri::command]
pub async fn set_config(
    config: AppConfig,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    tracing::info!("Updating config: {:?}", config);
    let mut current = state.config.lock().await;
    *current = config;
    Ok(())
}

/// Generate a persistent device ID using machine-specific info
fn get_device_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    // Use hostname as part of device ID
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        hostname.hash(&mut hasher);
    }

    // Use username
    if let Ok(user) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        user.hash(&mut hasher);
    }

    // Use home directory path
    if let Some(home) = dirs::home_dir() {
        home.to_string_lossy().hash(&mut hasher);
    }

    // Add OS info
    std::env::consts::OS.hash(&mut hasher);
    std::env::consts::ARCH.hash(&mut hasher);

    format!("oxidize-{:016x}", hasher.finish())
}

#[derive(Debug, Deserialize)]
struct DeviceAuthResponse {
    api_key: String,
    api_secret: String,
    #[serde(default)]
    created: bool,
}

/// Authenticate device and get API credentials
/// This is called on app startup to ensure the device has valid credentials
#[tauri::command]
pub async fn authenticate_device(
    state: tauri::State<'_, AppState>,
) -> Result<DeviceAuthCredentials, String> {
    // Check if we already have cached credentials
    {
        let creds = state.auth_credentials.lock().await;
        if let Some(ref c) = *creds {
            tracing::info!("Using cached device credentials");
            return Ok(c.clone());
        }
    }

    let device_id = get_device_id();
    tracing::info!("Authenticating device: {}", device_id);

    let url = format!("{}/api/auth/device", API_BASE_URL);

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .json(&serde_json::json!({
            "device_id": device_id,
            "platform": std::env::consts::OS,
            "app_version": env!("CARGO_PKG_VERSION")
        }))
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await
        .map_err(|e| format!("Failed to authenticate device: {}", e))?;

    if !response.status().is_success() {
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        return Err(format!("Device auth failed ({}): {}", status, text));
    }

    let auth_response: DeviceAuthResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse auth response: {}", e))?;

    let credentials = DeviceAuthCredentials {
        api_key: auth_response.api_key,
        api_secret: auth_response.api_secret,
    };

    // Cache credentials
    {
        let mut creds = state.auth_credentials.lock().await;
        *creds = Some(credentials.clone());
    }

    if auth_response.created {
        tracing::info!("New device registered successfully");
    } else {
        tracing::info!("Device authenticated successfully");
    }

    Ok(credentials)
}

/// Get current auth credentials (if authenticated)
#[tauri::command]
pub async fn get_auth_credentials(
    state: tauri::State<'_, AppState>,
) -> Result<Option<DeviceAuthCredentials>, String> {
    let creds = state.auth_credentials.lock().await;
    Ok(creds.clone())
}

#[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
const DAEMON_SOCKET: &str = "/var/run/oxidize/daemon.sock";
#[cfg(windows)]
const DAEMON_PIPE: &str = r"\\.\pipe\oxidize-daemon";

#[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
async fn send_daemon_command(cmd: &str) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(DAEMON_SOCKET)
        .await
        .map_err(|e| format!("Daemon not running: {}", e))?;

    let (reader, mut writer) = stream.into_split();

    writer
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e: std::io::Error| e.to_string())?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|e: std::io::Error| e.to_string())?;
    writer
        .flush()
        .await
        .map_err(|e: std::io::Error| e.to_string())?;

    let mut reader = BufReader::new(reader);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::from_str(&response).map_err(|e| format!("Invalid response: {}", e))
}

#[cfg(any(target_os = "android", target_os = "ios"))]
async fn send_daemon_command(_cmd: &str) -> Result<serde_json::Value, String> {
    Err("Daemon not available on mobile platforms".to_string())
}

#[cfg(windows)]
async fn send_daemon_command(cmd: &str) -> Result<serde_json::Value, String> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ClientOptions;

    let client = ClientOptions::new()
        .open(DAEMON_PIPE)
        .map_err(|e| format!("Daemon not running: {}", e))?;

    let (reader, writer) = tokio::io::split(client);
    let mut writer = writer;

    writer
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e: std::io::Error| e.to_string())?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|e: std::io::Error| e.to_string())?;
    writer
        .flush()
        .await
        .map_err(|e: std::io::Error| e.to_string())?;

    let mut reader = BufReader::new(reader);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::from_str(&response).map_err(|e| format!("Invalid response: {}", e))
}

/// Get the user's external/public IP address
async fn get_external_ip() -> Result<String, String> {
    let response = reqwest::get("https://api.ipify.org")
        .await
        .map_err(|e| format!("Failed to fetch IP: {}", e))?
        .text()
        .await
        .map_err(|e| format!("Failed to read IP: {}", e))?;
    Ok(response.trim().to_string())
}

/// Get the relay server's external IPv4 address
async fn get_server_ip(server_address: &str) -> Result<String, String> {
    // Return the server IP directly (already resolved from API)
    Ok(server_address.to_string())
}

async fn is_daemon_running() -> bool {
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        false
    }
    #[cfg(all(unix, not(target_os = "android"), not(target_os = "ios")))]
    {
        std::path::Path::new(DAEMON_SOCKET).exists()
            && send_daemon_command(r#"{"type":"Ping"}"#).await.is_ok()
    }
    #[cfg(windows)]
    {
        send_daemon_command(r#"{"type":"Ping"}"#).await.is_ok()
    }
}

async fn daemon_connect(server_id: String, server_address: String) -> Result<String, String> {
    let cmd = serde_json::json!({
        "type": "Connect",
        "server_id": server_id,
        "server_address": server_address
    })
    .to_string();
    let response = send_daemon_command(&cmd).await?;

    if response["success"].as_bool().unwrap_or(false) {
        Ok(response["message"]
            .as_str()
            .unwrap_or("Connected")
            .to_string())
    } else {
        Err(response["message"].as_str().unwrap_or("Failed").to_string())
    }
}

/// Check if daemon is installed and running
#[tauri::command]
pub async fn is_daemon_available() -> Result<bool, String> {
    Ok(is_daemon_running().await)
}

/// Get daemon status
#[tauri::command]
pub async fn daemon_get_status() -> Result<serde_json::Value, String> {
    if !is_daemon_running().await {
        return Ok(serde_json::json!({
            "connected": false,
            "daemon_running": false
        }));
    }

    let response = send_daemon_command(r#"{"type":"Status"}"#).await?;
    let mut data = response["data"].clone();
    data["daemon_running"] = serde_json::json!(true);
    Ok(data)
}

/// Find the daemon binary path
#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn find_daemon_binary(app: &tauri::AppHandle) -> Result<String, String> {
    // Try to find bundled daemon in resource directory (for installed app)
    if let Ok(resource_dir) = app.path().resource_dir() {
        #[cfg(windows)]
        let daemon_name = "oxidize-daemon.exe";
        #[cfg(not(windows))]
        let daemon_name = "oxidize-daemon";

        let sidecar_path = resource_dir.join(daemon_name);
        if sidecar_path.exists() {
            tracing::info!("Found daemon at resource path: {:?}", sidecar_path);
            return Ok(sidecar_path.to_string_lossy().to_string());
        }
    }

    // Fallback to development/system paths
    #[cfg(windows)]
    let fallback_paths = [
        r"..\..\..\target\release\oxidize-daemon.exe",
        r"..\..\target\release\oxidize-daemon.exe",
    ];

    #[cfg(not(windows))]
    let fallback_paths = [
        "../../../target/release/oxidize-daemon",
        "../../target/release/oxidize-daemon",
        "/usr/bin/oxidize-daemon",
        "/usr/local/bin/oxidize-daemon",
    ];

    for path in fallback_paths {
        let full_path = std::path::Path::new(path);
        if full_path.exists() {
            let canonical = full_path
                .canonicalize()
                .map_err(|e| e.to_string())?
                .to_string_lossy()
                .to_string();
            tracing::info!("Found daemon at fallback path: {}", path);
            return Ok(canonical);
        }
    }

    Err(
        "Daemon binary not found. The app may not have been installed correctly. Please reinstall."
            .to_string(),
    )
}

/// Install daemon with elevated privileges (Linux)
#[tauri::command]
#[cfg(target_os = "linux")]
pub async fn install_daemon(app: tauri::AppHandle) -> Result<String, String> {
    tracing::info!("Installing daemon (Linux)...");
    let daemon_bin = find_daemon_binary(&app)?;
    tracing::info!("Found daemon at: {}", daemon_bin);

    let install_script = format!(
        r#"
        exec > /tmp/oxidize-install.log 2>&1
        echo "=== Oxidize in-app install started at $(date) ==="
        mkdir -p /var/run/oxidize 2>/dev/null || true
        mkdir -p /etc/oxidize 2>/dev/null || true
        cp "{}" /usr/local/bin/oxidize-daemon 2>/dev/null || true
        chmod 755 /usr/local/bin/oxidize-daemon 2>/dev/null || true
        
        cat > /etc/systemd/system/oxidize-daemon.service << 'EOF'
[Unit]
Description=Oxidize Network Relay Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/oxidize-daemon
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info
PrivateTmp=true
ReadWritePaths=/var/run/oxidize

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload 2>/dev/null || true
        systemctl enable oxidize-daemon 2>/dev/null || true
        systemctl start oxidize-daemon 2>/dev/null || true
        echo "=== Install complete ==="
        exit 0
        "#,
        daemon_bin
    );

    let output = std::process::Command::new("pkexec")
        .arg("bash")
        .arg("-c")
        .arg(&install_script)
        .output()
        .map_err(|e| format!("Failed to run installer: {}", e))?;

    if output.status.success() {
        tracing::info!("Daemon installed successfully");
        Ok("Daemon installed and started".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Install failed: {}", stderr);
        Err(format!("Installation failed: {}", stderr))
    }
}

/// Install daemon with elevated privileges (macOS)
#[tauri::command]
#[cfg(target_os = "macos")]
pub async fn install_daemon(app: tauri::AppHandle) -> Result<String, String> {
    tracing::info!("Installing daemon (macOS)...");
    let daemon_bin = find_daemon_binary(&app)?;
    tracing::info!("Found daemon at: {}", daemon_bin);

    let install_script = format!(
        r#"
        mkdir -p /var/run/oxidize
        cp "{}" /usr/local/bin/oxidize-daemon
        chmod +x /usr/local/bin/oxidize-daemon
        
        cat > /Library/LaunchDaemons/com.oxidize.daemon.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.oxidize.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/oxidize-daemon</string>
    </array>
    <key>UserName</key>
    <string>root</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/oxidize-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/oxidize-daemon.log</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
EOF
        
        launchctl unload /Library/LaunchDaemons/com.oxidize.daemon.plist 2>/dev/null || true
        launchctl load /Library/LaunchDaemons/com.oxidize.daemon.plist
        "#,
        daemon_bin
    );

    // Use osascript to run with admin privileges
    let escaped_script = install_script.replace('"', r#"\""#).replace('\n', " ");
    let output = std::process::Command::new("osascript")
        .arg("-e")
        .arg(format!(
            r#"do shell script "{}" with administrator privileges"#,
            escaped_script
        ))
        .output()
        .map_err(|e| format!("Failed to run installer: {}", e))?;

    if output.status.success() {
        tracing::info!("Daemon installed successfully");
        Ok("Daemon installed and started".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Install failed: {}", stderr);
        Err(format!("Installation failed: {}", stderr))
    }
}

/// Install daemon with elevated privileges (Windows)
#[tauri::command]
#[cfg(target_os = "windows")]
pub async fn install_daemon(app: tauri::AppHandle) -> Result<String, String> {
    tracing::info!("Installing daemon (Windows)...");
    let daemon_bin = find_daemon_binary(&app)?;
    tracing::info!("Found daemon at: {}", daemon_bin);

    let install_script = format!(
        r#"
        $ErrorActionPreference = "Stop"
        
        Stop-Service -Name "OxidizeDaemon" -Force -ErrorAction SilentlyContinue
        sc.exe delete OxidizeDaemon 2>$null
        Start-Sleep -Seconds 1
        
        $targetDir = "$env:ProgramFiles\Oxidize"
        New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
        Copy-Item "{}" -Destination "$targetDir\oxidize-daemon.exe" -Force
        
        sc.exe create OxidizeDaemon binPath= "$targetDir\oxidize-daemon.exe" DisplayName= "Oxidize Network Relay Daemon" start= auto obj= LocalSystem
        sc.exe failure OxidizeDaemon reset= 86400 actions= restart/5000/restart/10000/restart/30000
        sc.exe description OxidizeDaemon "Oxidize network relay daemon for traffic tunneling"
        
        netsh advfirewall firewall delete rule name="Oxidize Daemon" 2>$null
        netsh advfirewall firewall add rule name="Oxidize Daemon" dir=out action=allow program="$targetDir\oxidize-daemon.exe"
        netsh advfirewall firewall add rule name="Oxidize Daemon In" dir=in action=allow program="$targetDir\oxidize-daemon.exe"
        
        Start-Service -Name "OxidizeDaemon"
        "#,
        daemon_bin.replace('\\', "\\\\")
    );

    let escaped_script = install_script.replace('\'', "''");
    let output = std::process::Command::new("powershell")
        .arg("-Command")
        .arg(format!(
            "Start-Process powershell -Verb RunAs -Wait -ArgumentList '-Command', '{}'",
            escaped_script
        ))
        .output()
        .map_err(|e| format!("Failed to run installer: {}", e))?;

    if output.status.success() {
        tracing::info!("Daemon installed successfully");
        Ok("Daemon installed and started".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Install failed: {}", stderr);
        Err(format!("Installation failed: {}", stderr))
    }
}

/// Install daemon - mobile stub
#[tauri::command]
#[cfg(any(target_os = "android", target_os = "ios"))]
pub async fn install_daemon() -> Result<String, String> {
    Err(
        "Daemon installation not available on mobile. VPN functionality uses system APIs."
            .to_string(),
    )
}

/// Uninstall daemon (desktop only)
#[tauri::command]
#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub async fn uninstall_daemon() -> Result<String, String> {
    tracing::info!("Uninstalling daemon...");

    // First, try to disconnect and cleanup if daemon is running
    if is_daemon_running().await {
        let _ = send_daemon_command(r#"{"type":"Disconnect"}"#).await;
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    // Use pkexec to stop and remove the daemon
    let uninstall_script = r#"
        exec > /tmp/oxidize-uninstall.log 2>&1
        echo "=== Oxidize uninstall started at $(date) ==="
        systemctl stop oxidize-daemon 2>/dev/null || true
        systemctl disable oxidize-daemon 2>/dev/null || true
        rm -f /etc/systemd/system/oxidize-daemon.service 2>/dev/null || true
        rm -f /usr/local/bin/oxidize-daemon 2>/dev/null || true
        rm -f /usr/bin/oxidize-daemon 2>/dev/null || true
        rm -rf /var/run/oxidize 2>/dev/null || true
        rm -rf /etc/oxidize 2>/dev/null || true
        systemctl daemon-reload 2>/dev/null || true
        echo "=== Uninstall complete ==="
        exit 0
    "#;

    let output = std::process::Command::new("pkexec")
        .arg("bash")
        .arg("-c")
        .arg(uninstall_script)
        .output()
        .map_err(|e| format!("Failed to run uninstaller: {}", e))?;

    if output.status.success() {
        tracing::info!("Daemon uninstalled successfully");
        Ok("Daemon uninstalled".to_string())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!("Uninstall failed: {}", stderr);
        Err(format!("Uninstallation failed: {}", stderr))
    }
}

/// Uninstall daemon - mobile stub
#[tauri::command]
#[cfg(any(target_os = "android", target_os = "ios"))]
pub async fn uninstall_daemon() -> Result<String, String> {
    Err("Daemon uninstallation not available on mobile.".to_string())
}

// ============================================================================
// Mobile-specific commands (no daemon required)
// ============================================================================

/// Mobile connect - uses direct relay-client instead of daemon
#[tauri::command]
#[cfg(any(target_os = "android", target_os = "ios"))]
pub async fn mobile_connect(
    server_id: String,
    server_address: String,
    mobile_state: tauri::State<'_, crate::mobile_client::MobileClientState>,
) -> Result<ConnectionStatus, String> {
    use std::net::SocketAddr;

    tracing::info!("Mobile connecting to {} ({})", server_id, server_address);

    let addr: SocketAddr = format!("{}:51820", server_address)
        .parse()
        .map_err(|e| format!("Invalid server address: {}", e))?;

    mobile_state.connect(server_id.clone(), addr).await?;

    crate::set_connected(true);

    let stats = mobile_state.get_stats();

    Ok(ConnectionStatus {
        connected: true,
        server: Some(server_id),
        ip: None, // Will be assigned by server
        original_ip: None,
        uptime_secs: stats.uptime_secs,
        bytes_sent: stats.bytes_sent,
        bytes_received: stats.bytes_received,
        packets_sent: stats.packets_sent,
        packets_received: stats.packets_received,
        compression_saved: 0,
        latency_ms: None,
        fec_recovered: 0,
        fec_sent: 0,
        loss_predictions: 0,
        congestion_adjustments: 0,
        path_switches: 0,
    })
}

/// Mobile disconnect
#[tauri::command]
#[cfg(any(target_os = "android", target_os = "ios"))]
pub async fn mobile_disconnect(
    mobile_state: tauri::State<'_, crate::mobile_client::MobileClientState>,
) -> Result<String, String> {
    mobile_state.disconnect().await?;
    crate::set_connected(false);
    Ok("Disconnected".to_string())
}

/// Mobile get status
#[tauri::command]
#[cfg(any(target_os = "android", target_os = "ios"))]
pub async fn mobile_get_status(
    mobile_state: tauri::State<'_, crate::mobile_client::MobileClientState>,
) -> Result<ConnectionStatus, String> {
    let stats = mobile_state.get_stats();
    let server_id = mobile_state.server_id().await;

    Ok(ConnectionStatus {
        connected: stats.connected,
        server: server_id,
        ip: None,
        original_ip: None,
        uptime_secs: stats.uptime_secs,
        bytes_sent: stats.bytes_sent,
        bytes_received: stats.bytes_received,
        packets_sent: stats.packets_sent,
        packets_received: stats.packets_received,
        compression_saved: 0,
        latency_ms: None,
        fec_recovered: 0,
        fec_sent: 0,
        loss_predictions: 0,
        congestion_adjustments: 0,
        path_switches: 0,
    })
}
