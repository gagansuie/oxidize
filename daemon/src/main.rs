use anyhow::{Context, Result};
use oxidize_common::oxtunnel_client::{CaptureConfig, PacketCaptureService};
// AF_XDP kernel bypass for bare metal packet capture (always enabled on Linux)
#[cfg(target_os = "linux")]
use oxidize_common::quic_xdp::{QuicXdpConfig, QuicXdpRuntime};
use relay_client::{ClientConfig, RelayClient};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
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
const RELAY_HOST: &str = "relay.oxd.sh";
const RELAY_PORT: u16 = 4433;

/// Cross-platform IPC path
#[cfg(windows)]
const PIPE_NAME: &str = r"\\.\pipe\oxidize-daemon";

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
enum DaemonCommand {
    Connect { server_id: String },
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
    client_task: Option<tokio::task::JoinHandle<()>>,
    metrics: Option<oxidize_common::RelayMetrics>,
    connected_at: Option<std::time::Instant>,
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

    // AF_XDP kernel bypass mode - initialize QuicXdpRuntime (always on Linux)
    #[cfg(target_os = "linux")]
    let _xdp_runtime = {
        info!("📦 Initializing AF_XDP kernel bypass mode...");
        let xdp_config = QuicXdpConfig {
            interface: std::env::var("OXIDIZE_INTERFACE").unwrap_or_else(|_| "eth0".to_string()),
            num_queues: std::env::var("OXIDIZE_QUEUES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(4),
            zero_copy: true,
            port: 4433,
            batch_size: 64,
            ml_congestion: true,
            cpu_cores: std::env::var("OXIDIZE_CPU_CORES").unwrap_or_else(|_| "2,3,4,5".to_string()),
            ..Default::default()
        };
        match QuicXdpRuntime::new(xdp_config) {
            Ok(mut runtime) => {
                if let Err(e) = runtime.start() {
                    warn!(
                        "⚠️  Failed to start AF_XDP runtime: {} - falling back to standard mode",
                        e
                    );
                    None
                } else {
                    info!(
                        "✅ AF_XDP kernel bypass active - {} queues",
                        runtime.connection_count()
                    );
                    Some(runtime)
                }
            }
            Err(e) => {
                warn!("⚠️  AF_XDP not available: {} - using standard mode", e);
                None
            }
        }
    };
    #[cfg(not(target_os = "linux"))]
    {
        warn!("⚠️  AF_XDP kernel bypass only available on Linux - using standard mode");
    }

    let state = Arc::new(Mutex::new(DaemonState::default()));

    // Spawn signal handler for graceful shutdown
    let shutdown_state = state.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        warn!("Shutdown signal received, cleaning up...");

        // Abort client task (capture service is stopped internally)
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
        DaemonCommand::Connect { server_id } => handle_connect(server_id, state).await,
        DaemonCommand::Disconnect => handle_disconnect(state).await,
        DaemonCommand::Status => handle_status(state).await,
        DaemonCommand::Ping => DaemonResponse {
            success: true,
            message: "pong".to_string(),
            data: None,
        },
    }
}

async fn handle_connect(server_id: String, state: &Arc<Mutex<DaemonState>>) -> DaemonResponse {
    let mut state_guard = state.lock().await;

    if state_guard.connected {
        return DaemonResponse {
            success: false,
            message: "Already connected".to_string(),
            data: None,
        };
    }

    // Resolve server address
    let server_addr: SocketAddr = match format!("{}:{}", RELAY_HOST, RELAY_PORT)
        .parse::<SocketAddr>()
        .or_else(|_| {
            use std::net::ToSocketAddrs;
            format!("{}:{}", RELAY_HOST, RELAY_PORT)
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

    // STEP 1: Add iptables exclusion for relay server BEFORE anything else
    // This ensures our QUIC connection won't be intercepted by NFQUEUE
    info!(
        "📦 Adding iptables exclusion for relay: {}",
        server_addr.ip()
    );
    let _ = std::process::Command::new("iptables")
        .args([
            "-I",
            "OUTPUT",
            "-d",
            &server_addr.ip().to_string(),
            "-j",
            "ACCEPT",
        ])
        .output();

    // STEP 2: Create QUIC client
    let config = ClientConfig::default();
    let client = match RelayClient::new(server_addr, config).await {
        Ok(c) => c,
        Err(e) => {
            return DaemonResponse {
                success: false,
                message: format!("Failed to create client: {}", e),
                data: None,
            };
        }
    };

    let metrics = client.get_metrics().clone();

    // STEP 3: Establish QUIC connection BEFORE NFQUEUE setup
    // This is critical - NFQUEUE intercepts even with iptables exclusions
    let connection = match client.connect().await {
        Ok(conn) => conn,
        Err(e) => {
            return DaemonResponse {
                success: false,
                message: format!("QUIC connection failed: {}", e),
                data: None,
            };
        }
    };
    info!("✅ QUIC handshake complete to {}", server_addr);

    // STEP 4: Cross-platform packet capture using unified PacketCaptureService
    // Configure capture with relay server exclusion
    let capture_config = CaptureConfig {
        capture_tcp: true,
        capture_udp: true,
        exclude_ips: vec![server_addr.ip()],
        queue_num: 0,
    };

    // Start cross-platform packet capture service
    let capture_service = PacketCaptureService::new(capture_config);
    let (oxtunnel_rx, capture_handle) = capture_service.start();

    // Get platform name for logging
    let platform = PacketCaptureService::platform_name();

    // Spawn client task with pre-established connection
    let task = tokio::spawn(async move {
        info!("🚀 Starting relay client ({} mode)...", platform);
        info!("   ├─ Mode: {} packet capture", platform);
        info!("   ├─ QUIC datagrams: enabled");
        info!("   └─ Capturing TCP+UDP traffic");

        if let Err(e) = client.run_with_connection(connection, oxtunnel_rx).await {
            error!("Client error: {}", e);
        }

        // Stop capture service when client ends
        capture_service.stop();
        let _ = capture_handle.await;
        info!("Client task ended");
    });

    state_guard.connected = true;
    state_guard.server_id = Some(server_id.clone());
    state_guard.client_task = Some(task);
    state_guard.metrics = Some(metrics);
    state_guard.connected_at = Some(std::time::Instant::now());

    DaemonResponse {
        success: true,
        message: format!(
            "Connected to {} ({})",
            server_addr,
            PacketCaptureService::platform_name()
        ),
        data: Some(serde_json::json!({
            "server_id": server_id,
            "server_addr": server_addr.to_string(),
            "platform": PacketCaptureService::platform_name(),
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

    // Abort the client task (capture service is stopped internally when client ends)
    if let Some(task) = state_guard.client_task.take() {
        task.abort();
        info!("Client task aborted");
    }

    let uptime = state_guard
        .connected_at
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    let (bytes_sent, bytes_received, packets_sent, packets_received, compression_saved) =
        if let Some(ref metrics) = state_guard.metrics {
            (
                metrics
                    .bytes_sent
                    .load(std::sync::atomic::Ordering::Relaxed),
                metrics
                    .bytes_received
                    .load(std::sync::atomic::Ordering::Relaxed),
                metrics
                    .packets_sent
                    .load(std::sync::atomic::Ordering::Relaxed),
                metrics
                    .packets_received
                    .load(std::sync::atomic::Ordering::Relaxed),
                metrics
                    .compression_saved
                    .load(std::sync::atomic::Ordering::Relaxed),
            )
        } else {
            (0, 0, 0, 0, 0)
        };

    state_guard.connected = false;
    state_guard.server_id = None;
    state_guard.metrics = None;
    state_guard.connected_at = None;

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
            "compression_saved": compression_saved,
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
        compression_saved,
        fec_recovered,
        fec_sent,
        loss_predictions,
        congestion_adjustments,
        path_switches,
    ) = if let Some(ref metrics) = state_guard.metrics {
        (
            metrics
                .bytes_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .bytes_received
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .packets_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .packets_received
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .compression_saved
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .fec_packets_recovered
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .fec_packets_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .loss_predictions
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .congestion_adjustments
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .path_switches
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    } else {
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
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
            "uptime_secs": uptime,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "packets_sent": packets_sent,
            "packets_received": packets_received,
            "compression_saved": compression_saved,
            "fec_recovered": fec_recovered,
            "fec_sent": fec_sent,
            "loss_predictions": loss_predictions,
            "congestion_adjustments": congestion_adjustments,
            "path_switches": path_switches,
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
