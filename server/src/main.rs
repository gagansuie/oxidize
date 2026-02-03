use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use oxidize_common::auth::ServerAuthConfig;
use relay_server::config::Config;
use relay_server::graceful::{setup_signal_handlers, ShutdownCoordinator};
use relay_server::oxtunnel_server::{
    generate_client_config, generate_server_config, OxTunnelServer, OxTunnelServerConfig,
};
use relay_server::prometheus::PrometheusMetrics;

#[derive(Parser, Debug)]
#[command(name = "relay-server")]
#[command(about = "Oxidize - High-performance Network Relay Server with OxTunnel", long_about = None)]
struct Args {
    /// Listen address - uses [::] for dual-stack (IPv6 + IPv4) by default
    #[arg(short, long, default_value = "[::]:51820")]
    listen: SocketAddr,

    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[arg(short, long)]
    verbose: bool,

    /// Metrics server address - uses [::] for dual-stack
    #[arg(long, default_value = "[::]:9090")]
    metrics_addr: SocketAddr,

    #[arg(long)]
    disable_metrics: bool,

    /// HTTP server address - uses [::] for dual-stack
    #[arg(long, default_value = "[::]:80")]
    http_addr: SocketAddr,

    #[arg(long)]
    disable_http: bool,

    /// Maximum connections capacity (for load calculation)
    #[arg(long, default_value = "10000")]
    max_connections: u32,

    #[arg(long)]
    generate_config: bool,

    #[arg(long)]
    endpoint: Option<String>,

    /// Enable authentication (requires OXIDIZE_APP_PUBLIC_KEY and OXIDIZE_API_SECRET env vars)
    #[arg(long)]
    enable_auth: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if args.verbose {
        "relay_server=trace,oxidize_common=debug"
    } else {
        "relay_server=info,oxidize_common=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    // Handle config generation
    if args.generate_config {
        let endpoint = args
            .endpoint
            .unwrap_or_else(|| format!("{}:{}", args.listen.ip(), args.listen.port()));

        info!("Generating OxTunnel server configuration...");
        let (server_id_hex, _, _server_id) = generate_server_config()?;

        println!("\n=== OxTunnel Server Configuration ===");
        println!("Server ID: {}", server_id_hex);
        println!("Listen: {}", args.listen);

        println!("\n=== Client Configuration ===");
        let client_config = generate_client_config(&endpoint, &server_id_hex, None)?;
        println!("{}", client_config);

        println!("\nSave the client config to a JSON file for app import.");

        return Ok(());
    }

    info!("╔════════════════════════════════════════╗");
    info!(
        "║   Oxidize Server v{}                ║",
        env!("CARGO_PKG_VERSION")
    );
    info!("║   OxTunnel Protocol (no QUIC)          ║");
    info!("╚════════════════════════════════════════╝");

    let config = Config::load(&args.config).unwrap_or_else(|_| {
        warn!("Config file not found, using defaults");
        Config::default()
    });

    // Generate server ID
    let (server_id_hex, _, _) = generate_server_config()?;

    info!("╔════════════════════════════════════════════════════════════════╗");
    info!("║                    Server Configuration                         ║");
    info!("╠════════════════════════════════════════════════════════════════╣");
    info!("║ Server ID: {}  ║", &server_id_hex[..32]);
    info!("║ Listen: {:42} ║", args.listen.to_string());
    info!("╚════════════════════════════════════════════════════════════════╝");

    // Initialize OxTunnel server
    let server_config = OxTunnelServerConfig {
        listen_addr: args.listen,
        enable_encryption: true,
        enable_compression: config.enable_compression,
        compression_threshold: config.compression_threshold,
        enable_rohc: config.enable_rohc,
        rohc_max_size: config.rohc_max_size,
        enable_ai_engine: config.enable_ai_engine,
        keepalive_interval: Duration::from_secs(config.keepalive_interval),
        session_timeout: Duration::from_secs(config.connection_timeout),
        ..Default::default()
    };

    // Load auth config if enabled
    let auth_config = if args.enable_auth {
        match ServerAuthConfig::from_env() {
            Some(config) => {
                info!("🔐 Authentication ENABLED (loaded from environment)");
                Some(config)
            }
            None => {
                error!("❌ FATAL: --enable-auth requires OXIDIZE_APP_PUBLIC_KEY and OXIDIZE_API_SECRET env vars");
                return Err(anyhow::anyhow!("Missing auth environment variables"));
            }
        }
    } else {
        warn!("⚠️  Authentication DISABLED - server accepts all connections");
        None
    };

    let server = match OxTunnelServer::with_auth(server_config, auth_config).await {
        Ok(s) => s,
        Err(e) => {
            error!("❌ FATAL: Failed to initialize OxTunnel server: {}", e);
            return Err(e);
        }
    };

    info!("✅ OxTunnel server initialized on {}", args.listen);
    info!("📊 Max sessions: {}", config.max_connections);
    info!(
        "🗜️  Compression: {}",
        if config.enable_compression {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!("🔐 Encryption: ChaCha20-Poly1305");

    // Auto-display client config
    let endpoint = format!("{}:{}", args.listen.ip(), args.listen.port());
    let client_config = generate_client_config(&endpoint, &server_id_hex, None)?;

    info!("╔════════════════════════════════════════════════════════════════╗");
    info!("║                    Client Configuration                         ║");
    info!("╠════════════════════════════════════════════════════════════════╣");
    info!("║ Import this JSON config in the Oxidize app:                    ║");
    info!("╚════════════════════════════════════════════════════════════════╝");
    for line in client_config.lines() {
        info!("  {}", line);
    }

    // Setup graceful shutdown coordinator
    let shutdown_coordinator = Arc::new(ShutdownCoordinator::new(Duration::from_secs(30)));

    // Setup signal handlers for graceful shutdown
    setup_signal_handlers(shutdown_coordinator.clone()).await;

    info!("🔄 Graceful shutdown enabled (30s drain timeout)");

    // Start metrics server if not disabled
    if !args.disable_metrics {
        let metrics = PrometheusMetrics::new()?;
        let metrics_addr = args.metrics_addr;

        // Spawn task to periodically update tunnel metrics
        let metrics_clone = metrics.clone();
        let server_stats = server.stats();
        tokio::spawn(async move {
            use std::sync::atomic::Ordering;
            loop {
                tokio::time::sleep(Duration::from_secs(2)).await;
                metrics_clone.update_tunnel_stats(
                    server_stats.active_sessions.load(Ordering::Relaxed),
                    server_stats.handshakes_completed.load(Ordering::Relaxed),
                    server_stats.invalid_packets.load(Ordering::Relaxed),
                    server_stats.total_tx_bytes.load(Ordering::Relaxed),
                    server_stats.total_rx_bytes.load(Ordering::Relaxed),
                    server_stats.total_tx_packets.load(Ordering::Relaxed),
                    server_stats.total_rx_packets.load(Ordering::Relaxed),
                );
            }
        });

        tokio::spawn(async move {
            if let Err(e) = metrics.start_server(metrics_addr).await {
                error!("Metrics server error: {}", e);
            }
        });
        info!("📊 Metrics server on http://{}", args.metrics_addr);
    }

    // Start HTTP server on port 80 for Cloudflare Workers to reach
    if !args.disable_http {
        let http_addr = args.http_addr;
        let http_stats = server.stats();
        let max_connections = args.max_connections;
        tokio::spawn(async move {
            if let Err(e) =
                relay_server::prometheus::start_http_server(http_addr, http_stats, max_connections)
                    .await
            {
                error!("HTTP server error: {}", e);
            }
        });
        info!("🌐 HTTP server on http://{}", args.http_addr);
    }

    // Start stats push task if configured
    if let Some(stats_url) = config.stats_push_url.clone() {
        let push_stats = server.stats();
        let push_interval = Duration::from_secs(config.stats_push_interval_secs);
        let push_max_connections = args.max_connections;
        let stats_token = std::env::var("STATS_TOKEN").ok();

        if stats_token.is_none() {
            warn!("⚠️  STATS_TOKEN not set - stats push will fail authentication");
        }

        info!(
            "📤 Stats push to {} every {}s",
            stats_url, config.stats_push_interval_secs
        );

        tokio::spawn(async move {
            use std::sync::atomic::Ordering;
            let client = reqwest::Client::new();

            loop {
                tokio::time::sleep(push_interval).await;

                let connections = push_stats.active_sessions.load(Ordering::Relaxed);
                let tx_bytes = push_stats.total_tx_bytes.load(Ordering::Relaxed);
                let rx_bytes = push_stats.total_rx_bytes.load(Ordering::Relaxed);
                let tx_packets = push_stats.total_tx_packets.load(Ordering::Relaxed);
                let rx_packets = push_stats.total_rx_packets.load(Ordering::Relaxed);

                let load_percent = if push_max_connections > 0 {
                    ((connections as f64 / push_max_connections as f64) * 100.0).min(100.0) as u8
                } else {
                    0
                };

                let payload = serde_json::json!({
                    "connections": connections,
                    "max_connections": push_max_connections,
                    "load_percent": load_percent,
                    "tx_bytes": tx_bytes,
                    "rx_bytes": rx_bytes,
                    "tx_packets": tx_packets,
                    "rx_packets": rx_packets
                });

                let mut request = client.post(&stats_url).json(&payload);
                if let Some(ref token) = stats_token {
                    request = request.header("Authorization", format!("Bearer {}", token));
                }

                match request.send().await {
                    Ok(resp) if resp.status().is_success() => {
                        // Stats pushed successfully
                    }
                    Ok(resp) => {
                        warn!("Stats push failed: HTTP {}", resp.status());
                    }
                    Err(e) => {
                        warn!("Stats push error: {}", e);
                    }
                }
            }
        });
    }

    info!("🚀 OxTunnel server running...");

    // Use tokio::select! to run server and wait for shutdown concurrently
    let mut shutdown_rx = shutdown_coordinator.shutdown_receiver();

    tokio::select! {
        result = server.run() => {
            if let Err(e) = result {
                error!("OxTunnel server error: {}", e);
            }
        }
        _ = shutdown_rx.changed() => {
            info!("Shutdown signal received");
        }
    }

    // Graceful shutdown
    shutdown_coordinator.shutdown().await;

    info!("Server stopped");

    Ok(())
}
