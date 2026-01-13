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
use tracing::{debug, error, info, warn};

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

        // Cleanup NFQUEUE on shutdown
        cleanup_nfqueue_rules();

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

    // Setup NFQUEUE for packet capture
    info!("Setting up NFQUEUE packet capture...");
    setup_nfqueue_rules();

    // Create channel for NFQUEUE packets -> QUIC
    let (packet_tx, packet_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10000);
    let forward_metrics = metrics.clone();

    // Spawn NFQUEUE capture task (runs in blocking thread)
    let nfq_tx = packet_tx.clone();
    let nfq_metrics = forward_metrics.clone();
    std::thread::spawn(move || {
        if let Err(e) = run_nfqueue_capture(nfq_tx, nfq_metrics) {
            error!("NFQUEUE capture error: {}", e);
        }
    });

    // Spawn client task with packet forwarding
    let task = tokio::spawn(async move {
        info!("🚀 Starting HIGH-PERFORMANCE relay client...");
        info!("   ├─ NFQUEUE packet capture: enabled");
        info!("   ├─ QUIC datagrams: enabled");
        info!("   └─ Zero-copy forwarding: enabled");

        if let Err(e) = client.run_with_sender(packet_rx).await {
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
        message: format!("Connected to {} (NFQUEUE enabled)", server_addr),
        data: Some(serde_json::json!({
            "server_id": server_id,
            "server_addr": server_addr.to_string(),
            "nfqueue_enabled": true,
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

    // Cleanup NFQUEUE rules
    cleanup_nfqueue_rules();

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

/// Setup iptables rules to send UDP packets to NFQUEUE
fn setup_nfqueue_rules() {
    info!("Setting up NFQUEUE iptables rules...");

    // Clean up existing rules
    let cleanup = vec![
        "iptables -D OUTPUT -p udp -m owner ! --uid-owner 0 -j NFQUEUE --queue-num 0 2>/dev/null || true",
        "iptables -D OUTPUT -p udp --dport 4433 -j ACCEPT 2>/dev/null || true",
    ];

    for rule in &cleanup {
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg(rule)
            .output();
    }

    // Setup NFQUEUE rules
    // Key: Exclude our QUIC traffic (port 4433), capture everything else
    let rules = vec![
        // Allow our QUIC tunnel traffic (don't capture it)
        "iptables -I OUTPUT -p udp --dport 4433 -j ACCEPT",
        // Send all other outgoing UDP to NFQUEUE 0
        "iptables -A OUTPUT -p udp -m owner ! --uid-owner 0 -j NFQUEUE --queue-num 0 --queue-bypass",
    ];

    for rule in &rules {
        let output = std::process::Command::new("sh")
            .arg("-c")
            .arg(rule)
            .output();
        match output {
            Ok(o) if o.status.success() => {
                debug!("Applied rule: {}", rule);
            }
            Ok(o) => {
                warn!(
                    "Rule failed: {} - {}",
                    rule,
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => {
                error!("Failed to run rule: {} - {}", rule, e);
            }
        }
    }

    info!("✅ NFQUEUE rules configured (queue 0)");
}

/// Cleanup NFQUEUE rules
#[allow(dead_code)]
fn cleanup_nfqueue_rules() {
    let rules = vec![
        "iptables -D OUTPUT -p udp -m owner ! --uid-owner 0 -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true",
        "iptables -D OUTPUT -p udp --dport 4433 -j ACCEPT 2>/dev/null || true",
    ];

    for rule in &rules {
        let _ = std::process::Command::new("sh")
            .arg("-c")
            .arg(rule)
            .output();
    }

    info!("NFQUEUE rules cleaned up");
}

/// Run NFQUEUE packet capture (blocking, runs in separate thread)
fn run_nfqueue_capture(
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    metrics: oxidize_common::RelayMetrics,
) -> Result<()> {
    use nfq::{Queue, Verdict};

    info!("📡 Starting NFQUEUE capture on queue 0...");

    let mut queue = Queue::open().context("Failed to open NFQUEUE")?;

    queue.bind(0).context("Failed to bind to queue 0")?;

    info!("✅ NFQUEUE bound to queue 0 - capturing packets");

    let mut packet_count: u64 = 0;

    loop {
        match queue.recv() {
            Ok(mut msg) => {
                packet_count += 1;
                let payload = msg.get_payload();
                let len = payload.len();

                // Record metrics
                metrics.record_received(len as u64);

                // Log periodically
                if packet_count.is_multiple_of(100) {
                    info!(
                        "📦 Captured {} packets via NFQUEUE, last: {} bytes",
                        packet_count, len
                    );
                }

                // Send to QUIC channel (non-blocking try)
                let packet = payload.to_vec();
                if tx.blocking_send(packet).is_err() {
                    warn!("QUIC channel full/closed");
                }

                // Accept the packet (let it through, we're just copying)
                msg.set_verdict(Verdict::Accept);
                queue.verdict(msg).ok();
            }
            Err(e) => {
                if packet_count > 0 {
                    debug!("NFQUEUE recv error: {}", e);
                }
            }
        }
    }
}
