use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};

use relay_server::config::Config;
use relay_server::graceful::{setup_signal_handlers, ShutdownCoordinator};
use relay_server::mobile_server::{
    generate_client_config, generate_server_config, MobileServerConfig, MobileTunnelServer,
};
use relay_server::prometheus::PrometheusMetrics;

#[derive(Parser, Debug)]
#[command(name = "relay-server")]
#[command(about = "Oxidize - High-performance Network Relay Server with OxTunnel", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:4433")]
    listen: SocketAddr,

    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long, default_value = "0.0.0.0:9090")]
    metrics_addr: SocketAddr,

    #[arg(long)]
    disable_metrics: bool,

    #[arg(long)]
    generate_config: bool,

    #[arg(long)]
    endpoint: Option<String>,
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
    let server_config = MobileServerConfig {
        listen_addr: args.listen,
        enable_encryption: true,
        ..Default::default()
    };

    let server = match MobileTunnelServer::new(server_config).await {
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
                tokio::time::sleep(Duration::from_secs(5)).await;
                metrics_clone.update_tunnel_stats(
                    server_stats.active_sessions.load(Ordering::Relaxed),
                    server_stats.handshakes_completed.load(Ordering::Relaxed),
                    server_stats.invalid_packets.load(Ordering::Relaxed),
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
