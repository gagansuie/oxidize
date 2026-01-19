use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

use relay_server::config::Config;
use relay_server::graceful::{setup_signal_handlers, ShutdownCoordinator};
use relay_server::mobile_server::{
    generate_client_config, generate_server_config, MobileServerConfig, MobileTunnelServer,
};
use relay_server::prometheus::PrometheusMetrics;
#[cfg(target_os = "linux")]
use relay_server::quic_xdp_server::{QuicServerConfig, QuicXdpServer};
use relay_server::server::RelayServer;

#[derive(Parser, Debug)]
#[command(name = "relay-server")]
#[command(about = "Oxidize - High-performance Network Relay Server", long_about = None)]
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
    generate_mobile_config: bool,

    #[arg(long)]
    mobile_endpoint: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if args.verbose {
        "oxidize_server=trace,oxidize_common=debug"
    } else {
        "oxidize_server=info,oxidize_common=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    // Handle mobile tunnel config generation
    if args.generate_mobile_config {
        let endpoint = args
            .mobile_endpoint
            .unwrap_or_else(|| format!("{}:51820", args.listen.ip()));

        info!("Generating Mobile Tunnel server configuration...");
        let (server_id_hex, _, _server_id) = generate_server_config()?;

        println!("\n=== Mobile Tunnel Server Configuration ===");
        println!("Server ID: {}", server_id_hex);
        println!("\nAdd to your server config.toml:");
        println!("[oxtunnel]");
        println!("enable_oxtunnel = true");
        println!("oxtunnel_port = 51820");

        println!("\n=== Client Configuration ===");
        let client_config = generate_client_config(&endpoint, &server_id_hex, None)?;
        println!("{}", client_config);

        println!("\nSave the client config to a JSON file for mobile app import.");

        return Ok(());
    }

    info!("Starting Oxidize Server v{}", env!("CARGO_PKG_VERSION"));
    info!("Listening on {}", args.listen);
    info!("╔════════════════════════════════════════╗");
    info!(
        "║   Oxidize Server v{}                ║",
        env!("CARGO_PKG_VERSION")
    );
    info!("╚════════════════════════════════════════╝");

    let config = Config::load(&args.config).unwrap_or_else(|_| {
        warn!("Config file not found, using defaults");
        Config::default()
    });

    let server = Arc::new(RelayServer::new(args.listen, config).await?);

    // Initialize QuicXdpServer for AF_XDP kernel bypass if available
    #[cfg(target_os = "linux")]
    let _xdp_server = {
        info!("📦 Initializing QUIC-XDP server for kernel bypass...");
        let xdp_config = QuicServerConfig {
            interface: std::env::var("OXIDIZE_INTERFACE").unwrap_or_else(|_| "eth0".to_string()),
            port: args.listen.port(),
            workers: std::env::var("OXIDIZE_WORKERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(4),
            zero_copy: true,
            ml_congestion: true,
            batch_size: 64,
            cpu_cores: std::env::var("OXIDIZE_CPU_CORES").unwrap_or_else(|_| "2,3,4,5".to_string()),
            force_mode: None,
        };
        match QuicXdpServer::new(xdp_config) {
            Ok(xdp) => {
                info!("✅ QUIC-XDP server initialized in {:?} mode", xdp.mode());
                Some(xdp)
            }
            Err(e) => {
                warn!("⚠️  QUIC-XDP not available: {} - using standard Quinn", e);
                None
            }
        }
    };
    #[cfg(not(target_os = "linux"))]
    let _xdp_server: Option<()> = None;

    info!("🚀 Server listening on {}", args.listen);
    info!("📊 Max connections: {}", server.config().max_connections);
    info!(
        "🗜️  Compression: {}",
        if server.config().enable_compression {
            "enabled"
        } else {
            "disabled"
        }
    );

    if !args.disable_metrics {
        info!(
            "📈 Prometheus metrics available at http://{}/metrics",
            args.metrics_addr
        );

        let prom_metrics = PrometheusMetrics::new()?;
        let prom_clone = prom_metrics.clone();

        tokio::spawn(async move {
            if let Err(e) = prom_clone.start_server(args.metrics_addr).await {
                warn!("Prometheus server failed: {}", e);
            }
        });

        let metrics_server = server.clone();
        let prom_update = prom_metrics.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                let stats = metrics_server.get_metrics().get_stats();
                prom_update.update_from_relay_metrics(&stats);
            }
        });
    }

    let stats_server = server.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            let stats = stats_server.get_metrics().get_stats();
            stats.print_summary();
        }
    });

    // Start Mobile Tunnel server if enabled
    let config_ref = server.config();
    if config_ref.enable_oxtunnel {
        let oxtunnel_port = config_ref.oxtunnel_port.unwrap_or(51820);
        let oxtunnel_addr: SocketAddr = format!("0.0.0.0:{}", oxtunnel_port).parse()?;

        // Generate server ID
        let (server_id_hex, _, _) = generate_server_config()?;

        info!("╔════════════════════════════════════════════════════════════════╗");
        info!("║           Mobile Tunnel Server Configuration                    ║");
        info!("╠════════════════════════════════════════════════════════════════╣");
        info!("║ Server ID: {}  ║", &server_id_hex[..32]);
        info!("╚════════════════════════════════════════════════════════════════╝");

        let mobile_config = MobileServerConfig {
            listen_addr: oxtunnel_addr,
            enable_encryption: true,
            ..Default::default()
        };

        let mobile_server = MobileTunnelServer::new(mobile_config).await?;
        info!("📱 OxTunnel server listening on {}", oxtunnel_addr);

        // Auto-display client config for mobile users
        let endpoint = format!("{}:{}", args.listen.ip(), oxtunnel_port);
        let client_config = generate_client_config(&endpoint, &server_id_hex, None)?;

        info!("╔════════════════════════════════════════════════════════════════╗");
        info!("║              Mobile Client Configuration                        ║");
        info!("╠════════════════════════════════════════════════════════════════╣");
        info!("║ Import this JSON config in the Oxidize mobile app:             ║");
        info!("╚════════════════════════════════════════════════════════════════╝");
        for line in client_config.lines() {
            info!("  {}", line);
        }

        tokio::spawn(async move {
            if let Err(e) = mobile_server.run().await {
                warn!("Mobile Tunnel server error: {}", e);
            }
        });
    }

    // Setup graceful shutdown coordinator
    let shutdown_coordinator = Arc::new(ShutdownCoordinator::new(Duration::from_secs(30)));

    // Setup signal handlers for graceful shutdown
    setup_signal_handlers(shutdown_coordinator.clone()).await;

    info!("🔄 Graceful shutdown enabled (30s drain timeout)");
    info!("   Send SIGTERM/SIGINT to gracefully drain connections");

    // Run server with graceful shutdown support
    server.run_with_shutdown(shutdown_coordinator).await?;

    Ok(())
}
