use anyhow::{Context, Result};
use oxidize_common::oxtunnel_client::{CaptureConfig, PacketCaptureService, ResponseInjector};
use relay_client::client::ClientStats;
use relay_client::RelayClient;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(unix)]
const SOCKET_PATH: &str = "/var/run/oxidize/daemon.sock";
const RELAY_PORT: u16 = 51820;

/// Cross-platform IPC path
#[cfg(windows)]
const PIPE_NAME: &str = r"\\.\pipe\oxidize-daemon";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum DaemonCommand {
    Connect {
        server_id: String,
        /// Server IP address (from API)
        server_address: String,
    },
    Disconnect,
    Status,
    Ping,
}

#[derive(Debug, Serialize, Deserialize)]
struct DaemonResponse {
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

#[derive(Default)]
struct DaemonState {
    connected: bool,
    server_id: Option<String>,
    server_addr: Option<String>,
    client_task: Option<tokio::task::JoinHandle<()>>,
    client_stats: Option<Arc<ClientStats>>,
    connected_at: Option<std::time::Instant>,
    /// Reference to client for graceful disconnect
    client: Option<Arc<RelayClient>>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("oxidize_daemon=info".parse().unwrap())
                .add_directive("relay_client=info".parse().unwrap()),
        )
        .init();

    info!("Oxidize Daemon starting...");

    let state = Arc::new(Mutex::new(DaemonState::default()));

    // Spawn signal handler for graceful shutdown
    let shutdown_state = state.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        warn!("Shutdown signal received, cleaning up...");

        // Abort client task
        let mut state_guard = shutdown_state.lock().await;
        if let Some(task) = state_guard.client_task.take() {
            task.abort();
        }
        drop(state_guard);

        info!("Cleanup complete, exiting");
        std::process::exit(0);
    });

    // Platform-specific IPC listener
    #[cfg(unix)]
    {
        run_unix_listener(state).await?;
    }

    #[cfg(windows)]
    {
        run_windows_listener(state).await?;
    }

    Ok(())
}

#[cfg(unix)]
async fn run_unix_listener(state: Arc<Mutex<DaemonState>>) -> Result<()> {
    // Create socket directory
    let socket_dir = Path::new(SOCKET_PATH).parent().unwrap();
    if !socket_dir.exists() {
        std::fs::create_dir_all(socket_dir).context("Failed to create socket directory")?;
    }

    // Remove old socket if exists
    if Path::new(SOCKET_PATH).exists() {
        std::fs::remove_file(SOCKET_PATH).context("Failed to remove old socket")?;
    }

    // Create Unix socket listener
    let listener = UnixListener::bind(SOCKET_PATH).context("Failed to bind Unix socket")?;

    // Set socket permissions to allow user access
    std::fs::set_permissions(
        SOCKET_PATH,
        std::os::unix::fs::PermissionsExt::from_mode(0o666),
    )
    .context("Failed to set socket permissions")?;

    info!("Daemon listening on {}", SOCKET_PATH);

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state).await {
                        error!("Client handler error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Accept error: {}", e);
            }
        }
    }
}

/// Wait for shutdown signal (SIGTERM or SIGINT)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

#[cfg(unix)]
async fn handle_client(stream: UnixStream, state: Arc<Mutex<DaemonState>>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let response = match serde_json::from_str::<DaemonCommand>(trimmed) {
            Ok(cmd) => handle_command(cmd, &state).await,
            Err(e) => DaemonResponse {
                success: false,
                message: format!("Invalid command: {}", e),
                data: None,
            },
        };

        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        line.clear();
    }

    Ok(())
}

async fn handle_command(cmd: DaemonCommand, state: &Arc<Mutex<DaemonState>>) -> DaemonResponse {
    match cmd {
        DaemonCommand::Connect {
            server_id,
            server_address,
        } => handle_connect(server_id, server_address, state).await,
        DaemonCommand::Disconnect => handle_disconnect(state).await,
        DaemonCommand::Status => handle_status(state).await,
        DaemonCommand::Ping => DaemonResponse {
            success: true,
            message: "pong".to_string(),
            data: None,
        },
    }
}

async fn handle_connect(
    server_id: String,
    server_address: String,
    state: &Arc<Mutex<DaemonState>>,
) -> DaemonResponse {
    let mut state_guard = state.lock().await;

    if state_guard.connected {
        return DaemonResponse {
            success: false,
            message: "Already connected".to_string(),
            data: None,
        };
    }

    // Debug: log received server_address
    info!(
        "Received connect request: server_id={}, server_address='{}'",
        server_id, server_address
    );

    // Resolve server address from provided IP
    let server_addr: SocketAddr = match format!("{}:{}", server_address, RELAY_PORT)
        .parse::<SocketAddr>()
        .or_else(|_| {
            use std::net::ToSocketAddrs;
            format!("{}:{}", server_address, RELAY_PORT)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addrs| addrs.next())
                .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "No address"))
        }) {
        Ok(addr) => addr,
        Err(e) => {
            return DaemonResponse {
                success: false,
                message: format!("Failed to resolve server: {}", e),
                data: None,
            };
        }
    };

    info!("Connecting to relay: {}", server_addr);

    // NOTE: Relay server exclusion is now handled by PacketCaptureService
    // which properly cleans up old rules and adds new ones with correct ordering.
    // The exclusion rule is added at position 1 (top of chain) by PacketCaptureService.

    // Create OxTunnel client (TUN-only client path)

    let oxtunnel_config = relay_client::client::ClientConfig {
        server_addr,
        // TCP fallback on port 51821 (same host as UDP server)
        tcp_fallback_addr: Some(std::net::SocketAddr::new(server_addr.ip(), 51821)),
        transport_mode: relay_client::client::TransportMode::Auto,
        enable_encryption: true,
        encryption_key: None,
        enable_compression: true,
        compression_threshold: 512,
        enable_rohc: true,
        rohc_max_size: 1500,
        enable_ai_engine: true,
        keepalive_interval: std::time::Duration::from_secs(25),
        connection_timeout: std::time::Duration::from_secs(30),
        auth_config: None,
    };

    let client = match RelayClient::new(oxtunnel_config).await {
        Ok(c) => c,
        Err(e) => {
            return DaemonResponse {
                success: false,
                message: format!("Failed to create client: {}", e),
                data: None,
            };
        }
    };

    // STEP 3: Establish OxTunnel connection
    if let Err(e) = client.connect().await {
        return DaemonResponse {
            success: false,
            message: format!("OxTunnel connection failed: {}", e),
            data: None,
        };
    }
    info!("✅ OxTunnel handshake complete to {}", server_addr);

    // STEP 4: Configure TUN capture (full coverage)
    use oxidize_common::tun_device::{TunConfig, TunDevice};

    let config = TunConfig {
        name: "oxtun0".to_string(),
        address: "10.200.200.1".parse().unwrap(),
        netmask: 24,
        mtu: 1500,
        packet_info: false,
    };

    info!("Creating TUN device for full-coverage acceleration...");
    let device = match TunDevice::new(config.clone()) {
        Ok(dev) => {
            info!("✅ TUN device {} created", dev.name());
            Arc::new(std::sync::Mutex::new(dev))
        }
        Err(e) => {
            return DaemonResponse {
                success: false,
                message: format!("Failed to create TUN device: {}", e),
                data: None,
            };
        }
    };

    // Set up routing through TUN device
    if let Ok(tun) = device.lock() {
        if let Err(e) = tun.set_default_route(server_addr.ip()) {
            warn!("Failed to set default route: {}", e);
        }
    }

    let tun_device = Some(device);
    let tun_config = Some(config);

    // STEP 5: Configure packet capture
    let capture_config = CaptureConfig {
        capture_tcp: true,
        capture_udp: true,
        capture_icmp: true,
        exclude_ips: vec![server_addr.ip()],
        tun_config: tun_config.clone(),
        tun_fd: None,
    };

    let capture_tcp = capture_config.capture_tcp;
    let capture_udp = capture_config.capture_udp;
    let capture_icmp = capture_config.capture_icmp;

    // Start packet capture service
    let capture_service = PacketCaptureService::with_tun_device(
        capture_config,
        tun_device.as_ref().expect("TUN device missing").clone(),
    );
    let (oxtunnel_rx, capture_handle) = capture_service.start();

    // Create response injector (TUN)
    let response_injector = Arc::new(ResponseInjector::with_tun_device(
        tun_device.as_ref().expect("TUN device missing").clone(),
    ));
    info!(
        "✅ Response injector ready ({} mode)",
        capture_service.mode_name()
    );

    // Get capture mode name for logging
    let platform = capture_service.mode_name();

    // Wrap client in Arc for sharing between task and state (for graceful disconnect)
    let client = Arc::new(client);
    let client_for_task = Arc::clone(&client);

    // Get stats handle BEFORE moving client into task
    let client_stats = client.stats_handle();

    // Spawn client task with packet capture AND response injection
    let task = tokio::spawn(async move {
        info!("🚀 Starting relay client ({} mode)...", platform);
        info!("   ├─ Mode: {} packet capture", platform);
        info!("   ├─ OxTunnel protocol: enabled");
        info!("   ├─ Response injection: {}", platform);
        info!(
            "   └─ Capturing TCP: {}, UDP: {}, ICMP: {}",
            capture_tcp, capture_udp, capture_icmp
        );

        if let Err(e) = client_for_task
            .run_with_injection(oxtunnel_rx, response_injector)
            .await
        {
            error!("Client error: {}", e);
        }

        // Stop capture service when client ends
        capture_service.stop();
        let _ = capture_handle.await;
        info!("Client task ended");
    });

    state_guard.connected = true;
    state_guard.server_id = Some(server_id.clone());
    state_guard.server_addr = Some(server_addr.to_string());
    state_guard.client_task = Some(task);
    state_guard.client_stats = Some(client_stats);
    state_guard.connected_at = Some(std::time::Instant::now());
    state_guard.client = Some(client);

    DaemonResponse {
        success: true,
        message: format!("Connected to {} ({} mode)", server_addr, platform),
        data: Some(serde_json::json!({
            "server_id": server_id,
            "server_addr": server_addr.to_string(),
            "mode": platform,
            "tcp_enabled": true,
            "udp_enabled": true,
            "icmp_enabled": true,
        })),
    }
}

async fn handle_disconnect(state: &Arc<Mutex<DaemonState>>) -> DaemonResponse {
    let mut state_guard = state.lock().await;

    if !state_guard.connected {
        return DaemonResponse {
            success: false,
            message: "Not connected".to_string(),
            data: None,
        };
    }

    // Send DISCONNECT to server BEFORE aborting task (so server can clean up session)
    if let Some(ref client) = state_guard.client {
        info!("Sending DISCONNECT to server...");
        client.disconnect().await;
    }

    // Abort the client task
    if let Some(task) = state_guard.client_task.take() {
        task.abort();
        info!("Client task aborted");
    }

    // Brief delay to allow cleanup to complete before allowing reconnect
    drop(state_guard);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    let mut state_guard = state.lock().await;

    let uptime = state_guard
        .connected_at
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    let (bytes_sent, bytes_received, packets_sent, packets_received) =
        if let Some(ref stats) = state_guard.client_stats {
            (
                stats.bytes_sent.load(Ordering::Relaxed),
                stats.bytes_received.load(Ordering::Relaxed),
                stats.packets_sent.load(Ordering::Relaxed),
                stats.packets_received.load(Ordering::Relaxed),
            )
        } else {
            (0, 0, 0, 0)
        };

    state_guard.connected = false;
    state_guard.server_id = None;
    state_guard.server_addr = None;
    state_guard.client_stats = None;
    state_guard.connected_at = None;
    state_guard.client = None;

    info!(
        "Disconnected. Uptime: {}s, Sent: {}, Received: {}, Packets: {}/{}",
        uptime, bytes_sent, bytes_received, packets_sent, packets_received
    );

    DaemonResponse {
        success: true,
        message: "Disconnected".to_string(),
        data: Some(serde_json::json!({
            "uptime_secs": uptime,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "packets_sent": packets_sent,
            "packets_received": packets_received,
        })),
    }
}

async fn handle_status(state: &Arc<Mutex<DaemonState>>) -> DaemonResponse {
    let state_guard = state.lock().await;

    let (
        bytes_sent,
        bytes_received,
        packets_sent,
        packets_received,
        handshakes,
        compression_saved,
        fec_recovered,
        fec_sent,
        loss_predictions,
        congestion_adjustments,
        path_switches,
        tunnel_latency_us,
        oversized_packets,
        oversized_packets_fragmented,
        oversized_packets_dropped,
        oversized_fragments_sent,
    ) = if let Some(ref stats) = state_guard.client_stats {
        (
            stats.bytes_sent.load(Ordering::Relaxed),
            stats.bytes_received.load(Ordering::Relaxed),
            stats.packets_sent.load(Ordering::Relaxed),
            stats.packets_received.load(Ordering::Relaxed),
            stats.handshakes_completed.load(Ordering::Relaxed),
            stats.compression_saved.load(Ordering::Relaxed),
            stats.fec_recovered.load(Ordering::Relaxed),
            stats.fec_sent.load(Ordering::Relaxed),
            stats.loss_predictions.load(Ordering::Relaxed),
            stats.congestion_adjustments.load(Ordering::Relaxed),
            stats.path_switches.load(Ordering::Relaxed),
            stats.tunnel_latency_us.load(Ordering::Relaxed),
            stats.oversized_packets.load(Ordering::Relaxed),
            stats.oversized_packets_fragmented.load(Ordering::Relaxed),
            stats.oversized_packets_dropped.load(Ordering::Relaxed),
            stats.oversized_fragments_sent.load(Ordering::Relaxed),
        )
    } else {
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    };

    let uptime = state_guard
        .connected_at
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    DaemonResponse {
        success: true,
        message: if state_guard.connected {
            "connected"
        } else {
            "disconnected"
        }
        .to_string(),
        data: Some(serde_json::json!({
            "connected": state_guard.connected,
            "server_id": state_guard.server_id,
            "server_addr": state_guard.server_addr,
            "uptime_secs": uptime,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "packets_sent": packets_sent,
            "packets_received": packets_received,
            "handshakes_completed": handshakes,
            "compression_saved": compression_saved,
            "fec_recovered": fec_recovered,
            "fec_sent": fec_sent,
            "loss_predictions": loss_predictions,
            "congestion_adjustments": congestion_adjustments,
            "path_switches": path_switches,
            "tunnel_latency_us": tunnel_latency_us,
            "oversized_packets": oversized_packets,
            "oversized_packets_fragmented": oversized_packets_fragmented,
            "oversized_packets_dropped": oversized_packets_dropped,
            "oversized_fragments_sent": oversized_fragments_sent,
        })),
    }
}

/// Windows named pipe listener for IPC
#[cfg(windows)]
async fn run_windows_listener(state: Arc<Mutex<DaemonState>>) -> Result<()> {
    use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

    info!("Daemon listening on {}", PIPE_NAME);

    loop {
        // Create a new pipe instance
        let server = ServerOptions::new()
            .pipe_mode(PipeMode::Message)
            .create(PIPE_NAME)
            .context("Failed to create named pipe")?;

        // Wait for a client to connect
        server
            .connect()
            .await
            .context("Failed to accept pipe connection")?;

        let state = state.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_windows_client(server, state).await {
                error!("Client handler error: {}", e);
            }
        });
    }
}

/// Handle Windows named pipe client
#[cfg(windows)]
async fn handle_windows_client(
    pipe: tokio::net::windows::named_pipe::NamedPipeServer,
    state: Arc<Mutex<DaemonState>>,
) -> Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let (reader, mut writer) = tokio::io::split(pipe);
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    while reader.read_line(&mut line).await? > 0 {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            line.clear();
            continue;
        }

        let response = match serde_json::from_str::<DaemonCommand>(trimmed) {
            Ok(cmd) => handle_command(cmd, &state).await,
            Err(e) => DaemonResponse {
                success: false,
                message: format!("Invalid command: {}", e),
                data: None,
            },
        };

        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
        writer.flush().await?;

        line.clear();
    }

    Ok(())
}
