use anyhow::{Context, Result};
// OxTunnelConfig available for future daemon OxTunnel integration
#[allow(unused_imports)]
use oxidize_common::oxtunnel_client::OxTunnelConfig;
use oxidize_common::oxtunnel_protocol::{
    encode_packet, flags, PacketBatch, HEADER_SIZE, MAX_PACKET_SIZE,
};
use oxidize_common::packet_capture::{create_queue, QueueConfig, Verdict};
use relay_client::{ClientConfig, RelayClient};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::signal;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

// ============================================================================
// OxTunnel Batching for NFQUEUE
// ============================================================================

/// Simple packet batcher for OxTunnel encapsulation
/// Respects QUIC datagram MTU limits
#[allow(dead_code)]
struct PacketBatcher {
    packets: Vec<Vec<u8>>,
    total_size: usize,
    max_batch_size: usize,
    max_payload_size: usize, // Must fit within QUIC datagram MTU
    sequence: AtomicU32,
}

#[allow(dead_code)]
impl PacketBatcher {
    /// Create batcher with max_payload_size to fit within QUIC datagrams
    /// QUIC datagram MTU is typically ~1200 bytes, so use 1100 to be safe
    fn new(max_batch_size: usize, max_payload_size: usize) -> Self {
        Self {
            packets: Vec::with_capacity(max_batch_size),
            total_size: 0,
            max_batch_size,
            max_payload_size,
            sequence: AtomicU32::new(0),
        }
    }

    fn next_seq(&self) -> u32 {
        self.sequence.fetch_add(1, Ordering::Relaxed)
    }

    fn add(&mut self, packet: Vec<u8>) -> Option<Vec<u8>> {
        let new_size = self.total_size + packet.len() + 2; // +2 for length prefix
                                                           // Flush if adding this packet would exceed MTU or max batch count
        let should_flush = new_size > self.max_payload_size - HEADER_SIZE - 32
            || self.packets.len() >= self.max_batch_size;

        if should_flush && !self.packets.is_empty() {
            let result = self.flush();
            self.packets.push(packet);
            self.total_size = self.packets.last().map(|p| p.len() + 2).unwrap_or(0);
            return result;
        }

        self.packets.push(packet);
        self.total_size = new_size;
        None
    }

    fn flush(&mut self) -> Option<Vec<u8>> {
        if self.packets.is_empty() {
            return None;
        }

        let mut batch = PacketBatch::new();
        for pkt in &self.packets {
            batch.add(pkt);
        }
        self.packets.clear();
        self.total_size = 0;

        let mut payload = vec![0u8; MAX_PACKET_SIZE];
        let payload_len = match batch.encode(&mut payload) {
            Ok(len) => len,
            Err(_) => return None,
        };
        payload.truncate(payload_len);

        let seq = self.next_seq();
        let mut output = vec![0u8; HEADER_SIZE + payload.len() + 32];
        match encode_packet(&mut output, &payload, seq, flags::BATCH, None) {
            Ok(len) => {
                output.truncate(len);
                Some(output)
            }
            Err(_) => None,
        }
    }
}

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
    queue_task: Option<tokio::task::JoinHandle<()>>,
    queue_stop_flag: Option<Arc<AtomicBool>>,
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

    // Detect platform and packet queue method
    match create_queue() {
        Ok(queue) => {
            info!("📦 Packet queue: {}", queue.platform_name());
        }
        Err(e) => {
            warn!("⚠️  Packet queue not available: {}", e);
            warn!("   The daemon will still run but cannot intercept traffic");
        }
    }

    let state = Arc::new(Mutex::new(DaemonState::default()));

    // Spawn signal handler for graceful shutdown
    let shutdown_state = state.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        warn!("Shutdown signal received, cleaning up...");

        // Abort client and queue tasks
        let mut state_guard = shutdown_state.lock().await;
        if let Some(task) = state_guard.client_task.take() {
            task.abort();
        }
        if let Some(task) = state_guard.queue_task.take() {
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

    // STEP 4: Now setup NFQUEUE packet interception (requires root)
    let mut queue = match create_queue() {
        Ok(q) => q,
        Err(e) => {
            error!("❌ NFQUEUE not available: {}", e);
            error!("   Daemon must run as root for NFQUEUE packet interception.");
            return DaemonResponse {
                success: false,
                message: format!("NFQUEUE failed: {}. Ensure daemon runs as root.", e),
                data: None,
            };
        }
    };

    let platform = queue.platform_name().to_string();
    let platform_clone = platform.clone();
    info!("📦 Setting up NFQUEUE: {}", platform);

    // Configure queue - exclude relay server to prevent intercepting our own connection
    let mut queue_config = QueueConfig::default();
    if !queue_config.exclude_ports.contains(&RELAY_PORT) {
        queue_config.exclude_ports.push(RELAY_PORT);
    }
    queue_config.exclude_ips.push(server_addr.ip());

    // Bind to queue (this adds iptables rules with exclusions)
    if let Err(e) = queue.bind(queue_config) {
        error!("Failed to bind packet queue: {}", e);
        return DaemonResponse {
            success: false,
            message: format!("Failed to bind packet queue: {}", e),
            data: None,
        };
    }

    // Create channel for OxTunnel-encapsulated packets -> QUIC
    let (oxtunnel_tx, oxtunnel_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(10000);

    // Create stop flag for graceful shutdown
    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_flag_clone = stop_flag.clone();

    // Spawn queue reading task - send raw packets directly (no batching for now)
    let queue_task = tokio::task::spawn_blocking(move || {
        info!("📡 NFQUEUE capture started - sending raw packets");
        let mut packet_count: u64 = 0;
        let start = Instant::now();

        loop {
            // Check stop flag for graceful shutdown
            if stop_flag_clone.load(Ordering::Relaxed) {
                info!("📡 NFQUEUE stop signal received, cleaning up...");
                break;
            }

            match queue.recv() {
                Ok(packet) => {
                    packet_count += 1;

                    // Extract packet ID before taking ownership of data
                    let packet_id = packet.id;

                    // Send raw packet directly (server expects raw IP packets)
                    // Only send if packet fits in QUIC datagram (~1100 bytes payload limit)
                    if packet.data.len() <= 1100 {
                        let _ = oxtunnel_tx.blocking_send(packet.data);
                    }

                    // Accept the packet (forward it normally)
                    if let Err(e) = queue.set_verdict(packet_id, Verdict::Accept) {
                        error!("Failed to set verdict: {}", e);
                    }

                    // Log throughput periodically
                    #[allow(clippy::manual_is_multiple_of)]
                    if packet_count % 10000 == 0 {
                        let elapsed = start.elapsed().as_secs_f64();
                        let pps = packet_count as f64 / elapsed;
                        info!("📦 NFQUEUE: {} packets, {:.0} pps", packet_count, pps);
                    }
                }
                Err(e) => {
                    if !queue.is_bound() {
                        break;
                    }
                    error!("Queue recv error: {}", e);
                }
            }
        }

        // Explicit cleanup - unbind will clean up iptables
        info!("📡 NFQUEUE cleanup: unbinding queue...");
        if let Err(e) = queue.unbind() {
            error!("Failed to unbind queue: {}", e);
        }
        info!("NFQUEUE capture ended ({} packets)", packet_count);
    });

    // Spawn client task with pre-established connection
    let task = tokio::spawn(async move {
        info!("🚀 Starting relay client with raw packet forwarding...");
        info!("   ├─ Packet queue: {}", platform_clone);
        info!("   ├─ QUIC datagrams: enabled");
        info!("   └─ Raw packets: enabled (no batching)");

        if let Err(e) = client.run_with_connection(connection, oxtunnel_rx).await {
            error!("Client error: {}", e);
        }

        info!("Client task ended");
    });

    state_guard.connected = true;
    state_guard.server_id = Some(server_id.clone());
    state_guard.client_task = Some(task);
    state_guard.queue_task = Some(queue_task);
    state_guard.queue_stop_flag = Some(stop_flag);
    state_guard.metrics = Some(metrics);
    state_guard.connected_at = Some(std::time::Instant::now());

    DaemonResponse {
        success: true,
        message: format!("Connected to {} ({})", server_addr, platform),
        data: Some(serde_json::json!({
            "server_id": server_id,
            "server_addr": server_addr.to_string(),
            "packet_queue": true,
            "platform": platform,
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

    // Signal queue task to stop gracefully (so it can unbind NFQUEUE)
    if let Some(stop_flag) = state_guard.queue_stop_flag.take() {
        stop_flag.store(true, Ordering::Relaxed);
        info!("Queue stop signal sent");
    }

    // Wait for queue task to finish cleanup
    if let Some(task) = state_guard.queue_task.take() {
        // Give it time to clean up (max 2 seconds)
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), task).await;
        info!("Queue task stopped");
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
