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
    pub direct_latency_ms: Option<u32>,
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
    latency: String,
    load: u8,
    server_count: u32,
    server_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppConfig {
    /// Auto-connect on launch
    pub auto_connect: bool,
}

#[derive(Default)]
pub struct AppState {
    pub config: Mutex<AppConfig>,
    pub original_ip: Mutex<Option<String>>,
    pub direct_latency_ms: Mutex<Option<u32>>,
}

// Relay server endpoint (used for ping test)
const RELAY_HOST: &str = "relay.oxd.sh";
const RELAY_PORT: u16 = 4433;

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

    // Measure direct latency BEFORE connecting (for latency comparison)
    let direct_latency = ping_relay().await.ok();
    {
        let mut direct_lat = state.direct_latency_ms.lock().await;
        *direct_lat = direct_latency;
    }

    tracing::info!("Connecting via daemon with NFQUEUE packet capture");
    daemon_connect(server_id.clone()).await?;

    crate::set_connected(true);

    // Fetch the relay server's external IP (this is what UDP traffic appears as)
    let server_ip = get_server_ip().await.ok();

    // Measure latency through relay
    let relay_latency = ping_relay().await.ok();

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
        direct_latency_ms: direct_latency,
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
            direct_latency_ms: None,
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
        direct_latency_ms: None,
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
            direct_latency_ms: None,
        });
    }

    let data = daemon_get_status().await?;
    let connected = data
        .get("connected")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // Get stored original IP and direct latency from state
    let original_ip = state.original_ip.lock().await.clone();
    let direct_latency_ms = *state.direct_latency_ms.lock().await;

    if connected {
        // Fetch the relay server's external IP (this is what UDP traffic appears as)
        let server_ip = get_server_ip().await.ok();

        // Measure current relay latency
        let relay_latency = ping_relay().await.ok();

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
            latency_ms: relay_latency,
            direct_latency_ms,
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
        direct_latency_ms: None,
    })
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct RegionsResponse {
    regions: Vec<ApiRegion>,
    #[serde(default)]
    timestamp: String,
    #[serde(default)]
    error: Option<String>,
}

#[tauri::command]
pub async fn get_regions() -> Result<Vec<Region>, String> {
    let url = format!("{}/api/servers", API_BASE_URL);

    let response = reqwest::get(&url)
        .await
        .map_err(|e| format!("Failed to fetch regions: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("API returned status: {}", response.status()));
    }

    let api_response: RegionsResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if let Some(error) = api_response.error {
        return Err(format!("API error: {}", error));
    }

    let regions: Vec<Region> = api_response
        .regions
        .into_iter()
        .filter(|r| r.status == "online" || r.status == "maintenance")
        .map(|r| {
            let latency_ms = r.latency.trim_end_matches("ms").parse::<u32>().ok();

            Region {
                id: r.id,
                name: r.name,
                location: r.location,
                country_code: r.country_code,
                status: r.status,
                latency_ms,
                load: r.load,
                server_count: r.server_count,
                server_ids: r.server_ids,
            }
        })
        .collect();

    tracing::info!("Fetched {} regions from API", regions.len());
    Ok(regions)
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
pub async fn get_closest_region() -> Result<Region, String> {
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
    let regions = get_regions().await?;

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

/// Ping relay using TCP connection time (lightweight, no full QUIC setup)
#[tauri::command]
pub async fn ping_relay() -> Result<u32, String> {
    use std::time::Instant;
    use tokio::net::TcpStream;

    let server_addr: SocketAddr = format!("{}:{}", RELAY_HOST, RELAY_PORT)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve: {}", e))?
        .next()
        .ok_or_else(|| "No address found".to_string())?;

    // Measure TCP connection time as a proxy for RTT
    // This is lightweight and doesn't require creating a full QUIC client
    let start = Instant::now();

    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        TcpStream::connect(server_addr),
    )
    .await;

    let latency = match result {
        Ok(Ok(_stream)) => {
            // TCP handshake completed - RTT is approximately half the elapsed time
            // (SYN -> SYN-ACK -> ACK, we measure SYN to SYN-ACK which is ~1 RTT)
            start.elapsed().as_millis() as u32
        }
        Ok(Err(e)) => {
            tracing::warn!("TCP ping failed: {}", e);
            return Err(format!("Connection failed: {}", e));
        }
        Err(_) => {
            return Err("Connection timeout".to_string());
        }
    };

    Ok(latency)
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

/// Get the relay server's external IP address
async fn get_server_ip() -> Result<String, String> {
    #[derive(Deserialize)]
    struct IpResponse {
        ip: String,
    }

    let url = format!("http://{}:{}/ip", RELAY_HOST, 9090);
    let response: IpResponse = reqwest::get(&url)
        .await
        .map_err(|e| format!("Failed to fetch server IP: {}", e))?
        .json()
        .await
        .map_err(|e| format!("Failed to parse server IP: {}", e))?;
    Ok(response.ip)
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

async fn daemon_connect(server_id: String) -> Result<String, String> {
    let cmd = serde_json::json!({"type": "Connect", "server_id": server_id}).to_string();
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
        set -e
        mkdir -p /var/run/oxidize
        mkdir -p /etc/oxidize
        cp "{}" /usr/local/bin/oxidize-daemon
        chmod 755 /usr/local/bin/oxidize-daemon
        
        cat > /etc/oxidize/nfqueue-rules.sh << 'RULES'
#!/bin/bash
QUEUE_NUM=0
iptables -D OUTPUT -p udp -j NFQUEUE --queue-num $QUEUE_NUM 2>/dev/null || true
iptables -I OUTPUT -p udp -j NFQUEUE --queue-num $QUEUE_NUM --queue-bypass
RULES
        chmod +x /etc/oxidize/nfqueue-rules.sh
        
        cat > /etc/systemd/system/oxidize-daemon.service << 'EOF'
[Unit]
Description=Oxidize Network Relay Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStartPre=/etc/oxidize/nfqueue-rules.sh
ExecStart=/usr/local/bin/oxidize-daemon
ExecStopPost=/sbin/iptables -D OUTPUT -p udp -j NFQUEUE --queue-num 0 2>/dev/null || true
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=info
PrivateTmp=true
ReadWritePaths=/var/run/oxidize

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable oxidize-daemon
        systemctl start oxidize-daemon
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
        # Stop the daemon service
        systemctl stop oxidize-daemon 2>/dev/null || true
        systemctl disable oxidize-daemon 2>/dev/null || true
        
        # Remove service file
        rm -f /etc/systemd/system/oxidize-daemon.service
        
        # Remove daemon binary
        rm -f /usr/local/bin/oxidize-daemon
        
        # Remove socket directory
        rm -rf /var/run/oxidize
        
        
        # Reload systemd
        systemctl daemon-reload 2>/dev/null || true
        
        echo "Daemon uninstalled successfully"
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
