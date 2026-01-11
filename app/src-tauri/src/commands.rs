use oxidize_common::RelayMetrics;
use relay_client::{ClientConfig, RelayClient};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const API_BASE_URL: &str = "https://oxd.sh";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStatus {
    pub connected: bool,
    pub server: Option<String>,
    pub ip: Option<String>,
    pub uptime_secs: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    pub id: String,
    pub name: String,
    pub location: String,
    pub country_code: String,
    pub load: u8,
    pub latency_ms: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct ApiServer {
    id: String,
    name: String,
    region: String,
    location: String,
    status: String,
    latency: String,
    load: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct ServersResponse {
    servers: Vec<ApiServer>,
    regions: Vec<String>,
    timestamp: String,
    #[serde(default)]
    error: Option<String>,
}

fn region_to_country_code(location: &str) -> String {
    match location.to_lowercase().as_str() {
        s if s.contains("virginia")
            || s.contains("new york")
            || s.contains("los angeles")
            || s.contains("chicago")
            || s.contains("denver")
            || s.contains("dallas")
            || s.contains("san jose")
            || s.contains("seattle")
            || s.contains("miami")
            || s.contains("atlanta")
            || s.contains("boston")
            || s.contains("secaucus") =>
        {
            "US".to_string()
        }
        s if s.contains("toronto") || s.contains("montreal") => "CA".to_string(),
        s if s.contains("amsterdam") => "NL".to_string(),
        s if s.contains("paris") => "FR".to_string(),
        s if s.contains("frankfurt") => "DE".to_string(),
        s if s.contains("london") => "GB".to_string(),
        s if s.contains("madrid") => "ES".to_string(),
        s if s.contains("warsaw") => "PL".to_string(),
        s if s.contains("stockholm") => "SE".to_string(),
        s if s.contains("tokyo") => "JP".to_string(),
        s if s.contains("hong kong") => "HK".to_string(),
        s if s.contains("singapore") => "SG".to_string(),
        s if s.contains("sydney") => "AU".to_string(),
        s if s.contains("mumbai") => "IN".to_string(),
        s if s.contains("são paulo") || s.contains("sao paulo") => "BR".to_string(),
        s if s.contains("santiago") => "CL".to_string(),
        s if s.contains("johannesburg") => "ZA".to_string(),
        _ => "XX".to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Auto-connect on launch
    pub auto_connect: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            auto_connect: false,
        }
    }
}

pub struct VpnConnection {
    pub metrics: RelayMetrics,
    pub server_id: String,
    pub server_addr: SocketAddr,
    pub connected_at: Instant,
    pub task_handle: Option<JoinHandle<()>>,
}

#[allow(dead_code)]
pub struct AppState {
    pub config: Mutex<AppConfig>,
    pub current_server: Mutex<Option<String>>,
    pub vpn_connection: Arc<Mutex<Option<VpnConnection>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            config: Mutex::new(AppConfig::default()),
            current_server: Mutex::new(None),
            vpn_connection: Arc::new(Mutex::new(None)),
        }
    }
}

// Relay server endpoint
const RELAY_HOST: &str = "relay.oxd.sh";
const RELAY_PORT: u16 = 4433;

#[tauri::command]
pub async fn connect(
    server_id: String,
    state: tauri::State<'_, AppState>,
) -> Result<ConnectionStatus, String> {
    tracing::info!("Connecting to relay via server: {}", server_id);

    // Check if already connected
    {
        let conn = state.vpn_connection.lock().await;
        if conn.is_some() {
            return Err("Already connected. Disconnect first.".to_string());
        }
    }

    // Check if daemon is available for TPROXY optimization
    // If daemon is running, use it for transparent proxy (gaming/VoIP optimization)
    if is_daemon_running().await {
        tracing::info!("Daemon available - using daemon connection with TPROXY");
        let sid = server_id.clone();
        daemon_connect(server_id).await?;

        // Update global connected state so UI stays updated
        crate::set_connected(true);

        return Ok(ConnectionStatus {
            connected: true,
            server: Some(sid),
            ip: None,
            uptime_secs: 0,
            bytes_sent: 0,
            bytes_received: 0,
        });
    }

    tracing::info!("Daemon not running - using direct QUIC connection");

    // Resolve Fly.io relay endpoint
    let server_addr: SocketAddr = format!("{}:{}", RELAY_HOST, RELAY_PORT)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve relay address: {}", e))?
        .next()
        .ok_or_else(|| "No addresses found for relay".to_string())?;

    tracing::info!("Relay endpoint: {}", server_addr);

    // Create client config with defaults
    let config = ClientConfig::default();

    // Create the relay client
    let client = RelayClient::new(server_addr, config)
        .await
        .map_err(|e| format!("Failed to create relay client: {}", e))?;

    // Get metrics reference before moving client
    let metrics = client.get_metrics().clone();

    // Spawn background task to run the client (establishes QUIC connection, handles keepalive)
    let task_handle = tokio::spawn(async move {
        tracing::info!("Starting RelayClient background task...");
        if let Err(e) = client.run().await {
            tracing::error!("RelayClient error: {}", e);
        }
        tracing::info!("RelayClient background task ended");
    });

    // Store connection state with metrics and task handle
    let vpn_conn = VpnConnection {
        metrics,
        server_id: server_id.clone(),
        server_addr,
        connected_at: Instant::now(),
        task_handle: Some(task_handle),
    };

    {
        let mut conn = state.vpn_connection.lock().await;
        *conn = Some(vpn_conn);
    }

    tracing::info!(
        "RelayClient running with full QUIC connection to {}",
        server_addr
    );

    // Update global connected state
    crate::set_connected(true);

    tracing::info!("Relay client connected to {}", server_addr);

    Ok(ConnectionStatus {
        connected: true,
        server: Some(server_id),
        ip: Some(server_addr.ip().to_string()),
        uptime_secs: 0,
        bytes_sent: 0,
        bytes_received: 0,
    })
}

#[tauri::command]
pub async fn disconnect(state: tauri::State<'_, AppState>) -> Result<ConnectionStatus, String> {
    tracing::info!("Disconnecting...");

    // Check if we're using daemon mode first
    if is_daemon_running().await {
        tracing::info!("Disconnecting via daemon...");
        let response = send_daemon_command(r#"{"type":"Disconnect"}"#).await;
        if let Ok(resp) = response {
            let bytes_sent = resp["data"]["bytes_sent"].as_u64().unwrap_or(0);
            let bytes_received = resp["data"]["bytes_received"].as_u64().unwrap_or(0);
            let uptime_secs = resp["data"]["uptime_secs"].as_u64().unwrap_or(0);

            crate::set_connected(false);
            tracing::info!("Daemon disconnected");

            return Ok(ConnectionStatus {
                connected: false,
                server: None,
                ip: None,
                uptime_secs,
                bytes_sent,
                bytes_received,
            });
        }
    }

    // Get connection metrics and abort task (direct mode)
    let (bytes_sent, bytes_received, uptime_secs) = {
        let mut conn = state.vpn_connection.lock().await;
        if let Some(ref mut vpn) = *conn {
            let uptime = vpn.connected_at.elapsed().as_secs();
            let sent = vpn
                .metrics
                .bytes_sent
                .load(std::sync::atomic::Ordering::Relaxed);
            let received = vpn
                .metrics
                .bytes_received
                .load(std::sync::atomic::Ordering::Relaxed);

            // Abort the background task
            if let Some(handle) = vpn.task_handle.take() {
                handle.abort();
                tracing::info!("Aborted RelayClient background task");
            }

            (sent, received, uptime)
        } else {
            (0, 0, 0)
        }
    };

    // Clear the connection
    {
        let mut conn = state.vpn_connection.lock().await;
        *conn = None;
    }

    crate::set_connected(false);
    tracing::info!(
        "Disconnected. Sent: {} bytes, Received: {} bytes",
        bytes_sent,
        bytes_received
    );

    Ok(ConnectionStatus {
        connected: false,
        server: None,
        ip: None,
        uptime_secs,
        bytes_sent,
        bytes_received,
    })
}

#[tauri::command]
pub async fn get_status(state: tauri::State<'_, AppState>) -> Result<ConnectionStatus, String> {
    let conn = state.vpn_connection.lock().await;

    // Check local VPN connection first
    if let Some(ref vpn) = *conn {
        return Ok(ConnectionStatus {
            connected: true,
            server: Some(vpn.server_id.clone()),
            ip: Some(vpn.server_addr.ip().to_string()),
            uptime_secs: vpn.connected_at.elapsed().as_secs(),
            bytes_sent: vpn
                .metrics
                .bytes_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            bytes_received: vpn
                .metrics
                .bytes_received
                .load(std::sync::atomic::Ordering::Relaxed),
        });
    }

    // Drop the lock before async call
    drop(conn);

    // If no local connection, check daemon status
    if is_daemon_running().await {
        if let Ok(data) = daemon_get_status().await {
            let connected = data
                .get("connected")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if connected {
                return Ok(ConnectionStatus {
                    connected: true,
                    server: data
                        .get("server_id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    ip: None,
                    uptime_secs: data
                        .get("uptime_secs")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                    bytes_sent: data.get("bytes_sent").and_then(|v| v.as_u64()).unwrap_or(0),
                    bytes_received: data
                        .get("bytes_received")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0),
                });
            }
        }
    }

    Ok(ConnectionStatus {
        connected: false,
        server: None,
        ip: None,
        uptime_secs: 0,
        bytes_sent: 0,
        bytes_received: 0,
    })
}

#[tauri::command]
pub async fn get_servers() -> Result<Vec<Server>, String> {
    let url = format!("{}/api/servers", API_BASE_URL);

    let response = reqwest::get(&url)
        .await
        .map_err(|e| format!("Failed to fetch servers: {}", e))?;

    if !response.status().is_success() {
        return Err(format!("API returned status: {}", response.status()));
    }

    let api_response: ServersResponse = response
        .json()
        .await
        .map_err(|e| format!("Failed to parse response: {}", e))?;

    if let Some(error) = api_response.error {
        return Err(format!("API error: {}", error));
    }

    let servers: Vec<Server> = api_response
        .servers
        .into_iter()
        .filter(|s| s.status == "online")
        .map(|s| {
            let latency_ms = s.latency.trim_end_matches("ms").parse::<u32>().ok();

            Server {
                id: s.id,
                name: s.name,
                location: s.location.clone(),
                country_code: region_to_country_code(&s.location),
                load: s.load,
                latency_ms,
            }
        })
        .collect();

    tracing::info!("Fetched {} servers from API", servers.len());
    Ok(servers)
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

/// Ping relay using actual QUIC connection (measures real latency)
#[tauri::command]
pub async fn ping_relay() -> Result<u32, String> {
    use std::time::Instant;

    let server_addr: SocketAddr = format!("{}:{}", RELAY_HOST, RELAY_PORT)
        .to_socket_addrs()
        .map_err(|e| format!("Failed to resolve: {}", e))?
        .next()
        .ok_or_else(|| "No address found".to_string())?;

    // Use the actual RelayClient to measure QUIC connection latency
    let config = ClientConfig::default();
    let start = Instant::now();

    // Create client - this establishes the QUIC endpoint
    let client = RelayClient::new(server_addr, config)
        .await
        .map_err(|e| format!("Failed to create client: {}", e))?;

    let latency = start.elapsed().as_millis() as u32;

    // Client is dropped here, closing the connection
    drop(client);

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

const DAEMON_SOCKET: &str = "/var/run/oxidize/daemon.sock";

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
        .map_err(|e| e.to_string())?;
    writer.write_all(b"\n").await.map_err(|e| e.to_string())?;
    writer.flush().await.map_err(|e| e.to_string())?;

    let mut reader = BufReader::new(reader);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .await
        .map_err(|e| e.to_string())?;

    serde_json::from_str(&response).map_err(|e| format!("Invalid response: {}", e))
}

async fn is_daemon_running() -> bool {
    std::path::Path::new(DAEMON_SOCKET).exists()
        && send_daemon_command(r#"{"type":"Ping"}"#).await.is_ok()
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

/// Connect via daemon (Full Tunnel Mode)
#[tauri::command]
pub async fn daemon_connect_cmd(server_id: String) -> Result<String, String> {
    if !is_daemon_running().await {
        return Err(
            "Daemon not running. Please enable Full Tunnel Mode in Settings first.".to_string(),
        );
    }
    daemon_connect(server_id).await
}

/// Disconnect via daemon
#[tauri::command]
pub async fn daemon_disconnect_cmd() -> Result<String, String> {
    if !is_daemon_running().await {
        return Err("Daemon not running".to_string());
    }

    let response = send_daemon_command(r#"{"type":"Disconnect"}"#).await?;
    if response["success"].as_bool().unwrap_or(false) {
        Ok(response["message"]
            .as_str()
            .unwrap_or("Disconnected")
            .to_string())
    } else {
        Err(response["message"].as_str().unwrap_or("Failed").to_string())
    }
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

/// Install daemon with elevated privileges
#[tauri::command]
pub async fn install_daemon() -> Result<String, String> {
    tracing::info!("Installing daemon...");

    // Find the daemon binary
    let daemon_paths = [
        "../../../target/release/oxidize-daemon",
        "../../target/release/oxidize-daemon",
        "/usr/bin/oxidize-daemon",
        "/usr/local/bin/oxidize-daemon",
    ];

    let mut daemon_path: Option<String> = None;
    for path in daemon_paths {
        let full_path = std::path::Path::new(path);
        if full_path.exists() {
            daemon_path = Some(
                full_path
                    .canonicalize()
                    .map_err(|e| e.to_string())?
                    .to_string_lossy()
                    .to_string(),
            );
            break;
        }
    }

    let daemon_bin = daemon_path.ok_or_else(|| {
        "Daemon binary not found. Please build with: cargo build --release -p oxidize-daemon"
            .to_string()
    })?;

    tracing::info!("Found daemon at: {}", daemon_bin);

    // Use pkexec to install and start the daemon
    let install_script = format!(
        r#"
        mkdir -p /var/run/oxidize
        cp "{}" /usr/local/bin/oxidize-daemon
        chmod 755 /usr/local/bin/oxidize-daemon
        cat > /etc/systemd/system/oxidize-daemon.service << 'EOF'
[Unit]
Description=Oxidize Network Relay Daemon
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/oxidize-daemon
Restart=on-failure
RestartSec=5

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

/// Uninstall daemon
#[tauri::command]
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
        
        # Cleanup TPROXY iptables rules
        iptables -t mangle -F OXIDIZE_TPROXY 2>/dev/null || true
        iptables -t mangle -D PREROUTING -j OXIDIZE_TPROXY 2>/dev/null || true
        iptables -t mangle -X OXIDIZE_TPROXY 2>/dev/null || true
        ip rule del fwmark 1 lookup 100 2>/dev/null || true
        ip route del local 0.0.0.0/0 dev lo table 100 2>/dev/null || true
        
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
