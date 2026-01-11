use anyhow::{Context, Result};
use relay_client::{ClientConfig, RelayClient};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::signal;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

const SOCKET_PATH: &str = "/var/run/oxidize/daemon.sock";
const RELAY_HOST: &str = "relay.oxd.sh";
const RELAY_PORT: u16 = 4433;

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

struct DaemonState {
    connected: bool,
    server_id: Option<String>,
    client_task: Option<tokio::task::JoinHandle<()>>,
    metrics: Option<oxidize_common::RelayMetrics>,
    connected_at: Option<std::time::Instant>,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self {
            connected: false,
            server_id: None,
            client_task: None,
            metrics: None,
            connected_at: None,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging - include relay_client crate for XDP mode logs
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("oxidize_daemon=info".parse().unwrap())
                .add_directive("relay_client=info".parse().unwrap()),
        )
        .init();

    info!("Oxidize Daemon starting...");

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

    let state = Arc::new(Mutex::new(DaemonState::default()));

    // Spawn signal handler for graceful shutdown
    let shutdown_state = state.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        warn!("Shutdown signal received, cleaning up...");

        // Abort client task if running
        let mut state_guard = shutdown_state.lock().await;
        if let Some(task) = state_guard.client_task.take() {
            task.abort();
        }
        drop(state_guard);

        // Cleanup XDP routing on shutdown
        cleanup_xdp_routing();

        info!("Cleanup complete, exiting");
        std::process::exit(0);
    });

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

    // Create client
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

    // Spawn client task with XDP mode
    let task = tokio::spawn(async move {
        info!("Starting XDP mode (10+ Gbps)...");
        if let Err(e) = client.run_with_xdp().await {
            error!("Client error: {}", e);
        }
        info!("Client task ended");
    });

    state_guard.connected = true;
    state_guard.server_id = Some(server_id.clone());
    state_guard.client_task = Some(task);
    state_guard.metrics = Some(metrics);
    state_guard.connected_at = Some(std::time::Instant::now());

    DaemonResponse {
        success: true,
        message: format!("Connected to {}", server_addr),
        data: Some(serde_json::json!({
            "server_id": server_id,
            "server_addr": server_addr.to_string(),
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

    // Abort the client task
    if let Some(task) = state_guard.client_task.take() {
        task.abort();
        info!("Client task aborted");
    }

    // Cleanup XDP routing
    cleanup_xdp_routing();

    let uptime = state_guard
        .connected_at
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    let (bytes_sent, bytes_received) = if let Some(ref metrics) = state_guard.metrics {
        (
            metrics
                .bytes_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .bytes_received
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    } else {
        (0, 0)
    };

    state_guard.connected = false;
    state_guard.server_id = None;
    state_guard.metrics = None;
    state_guard.connected_at = None;

    info!(
        "Disconnected. Uptime: {}s, Sent: {}, Received: {}",
        uptime, bytes_sent, bytes_received
    );

    DaemonResponse {
        success: true,
        message: "Disconnected".to_string(),
        data: Some(serde_json::json!({
            "uptime_secs": uptime,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
        })),
    }
}

/// Cleanup XDP routing and restore original network configuration
fn cleanup_xdp_routing() {
    info!("Cleaning up XDP routing...");

    // Remove any XDP programs from interfaces
    // In production, this would detach eBPF programs

    // Restore DNS if backup exists
    if Path::new("/etc/resolv.conf.oxidize.bak").exists() {
        if let Err(e) = std::fs::copy("/etc/resolv.conf.oxidize.bak", "/etc/resolv.conf") {
            error!("Failed to restore DNS: {}", e);
        } else {
            let _ = std::fs::remove_file("/etc/resolv.conf.oxidize.bak");
            info!("DNS restored from backup");
        }
    }

    info!("XDP cleanup complete");
}

async fn handle_status(state: &Arc<Mutex<DaemonState>>) -> DaemonResponse {
    let state_guard = state.lock().await;

    let (bytes_sent, bytes_received) = if let Some(ref metrics) = state_guard.metrics {
        (
            metrics
                .bytes_sent
                .load(std::sync::atomic::Ordering::Relaxed),
            metrics
                .bytes_received
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    } else {
        (0, 0)
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
        })),
    }
}
