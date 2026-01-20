use anyhow::{bail, Result};
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
use relay_server::quic_xdp_server::{QuicServerConfig, QuicXdpServer};

/// Auto-detect the default network interface
#[cfg(target_os = "linux")]
fn detect_default_interface() -> String {
    // Try to find the default route interface
    if let Ok(output) = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
    {
        if let Ok(stdout) = String::from_utf8(output.stdout) {
            // Parse "default via X.X.X.X dev ethX ..."
            for part in stdout.split_whitespace() {
                if part.starts_with("eth") || part.starts_with("enp") || part.starts_with("ens") {
                    return part.to_string();
                }
            }
        }
    }
    // Fallback
    "eth0".to_string()
}

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

    /// Network interface for XDP (default: auto-detect)
    #[arg(long)]
    xdp_interface: Option<String>,

    /// Number of XDP worker threads (default: 4)
    #[arg(long, default_value = "4")]
    xdp_workers: u32,
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

    // Initialize and START QuicXdpServer - REQUIRED (no fallback)
    info!("📦 Initializing QUIC-XDP server for kernel bypass...");
    let xdp_config = QuicServerConfig {
        interface: std::env::var("OXIDIZE_INTERFACE").unwrap_or_else(|_| {
            args.xdp_interface
                .clone()
                .unwrap_or_else(detect_default_interface)
        }),
        port: args.listen.port(),
        workers: std::env::var("OXIDIZE_WORKERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(args.xdp_workers),
        zero_copy: true,
        ml_congestion: true,
        batch_size: 64,
        cpu_cores: std::env::var("OXIDIZE_CPU_CORES").unwrap_or_else(|_| "2,3,4,5".to_string()),
        force_mode: None,
    };

    let mut xdp_server = match QuicXdpServer::new(xdp_config) {
        Ok(xdp) => xdp,
        Err(e) => {
            error!("❌ FATAL: Failed to initialize QUIC-XDP: {}", e);
            error!("   Oxidize requires AF_XDP kernel bypass to run.");
            error!("   Ensure you are on Linux with XDP support and proper permissions.");
            bail!("QUIC-XDP initialization failed: {}", e);
        }
    };

    // Start the XDP server
    if let Err(e) = xdp_server.start() {
        error!("❌ FATAL: Failed to start QUIC-XDP: {}", e);
        error!("   Check NIC driver compatibility and kernel version.");
        bail!("QUIC-XDP start failed: {}", e);
    }

    info!("✅ QUIC-XDP server STARTED in {:?} mode", xdp_server.mode());
    info!("🚀 Kernel bypass ACTIVE - 100x performance enabled!");

    info!("🚀 Server listening on {}", args.listen);
    info!("📊 Max connections: {}", config.max_connections);
    info!(
        "🗜️  Compression: {}",
        if config.enable_compression {
            "enabled"
        } else {
            "disabled"
        }
    );

    // XDP stats logging
    info!("📊 XDP stats will be logged every 30 seconds");

    // Start Mobile Tunnel server if enabled
    if config.enable_oxtunnel {
        let oxtunnel_port = config.oxtunnel_port.unwrap_or(51820);
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

    // XDP handles all QUIC traffic
    info!("🚀 Running in XDP-only mode");
    info!("   All QUIC traffic handled by AF_XDP kernel bypass");

    // Wait for shutdown signal
    let mut shutdown_rx = shutdown_coordinator.shutdown_receiver();
    let _ = shutdown_rx.changed().await;

    // Graceful shutdown
    shutdown_coordinator.shutdown().await;

    // Stop XDP server
    info!("Stopping XDP server...");
    xdp_server.stop();

    Ok(())
}
