use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

mod cache;
mod config;
mod connection;
mod prometheus;
mod server;
mod tls;
mod wireguard;

use config::Config;
use server::RelayServer;
use wireguard::{generate_client_config, generate_server_config, WireGuardServer};

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
    generate_wg_config: bool,

    #[arg(long)]
    wg_endpoint: Option<String>,
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

    // Handle WireGuard config generation
    if args.generate_wg_config {
        let endpoint = args
            .wg_endpoint
            .unwrap_or_else(|| format!("{}:51820", args.listen.ip()));

        info!("Generating WireGuard server configuration...");
        let (private_key, public_key, _key_bytes) = generate_server_config()?;

        println!("\n=== WireGuard Server Configuration ===");
        println!("Server Private Key: {}", private_key);
        println!("Server Public Key: {}", public_key);
        println!("\nAdd to your server config.toml:");
        println!("[wireguard]");
        println!("enable_wireguard = true");
        println!("wireguard_port = 51820");
        println!("wireguard_private_key = \"{}\"", private_key);

        println!("\n=== Client Configuration ===");
        let client_config = generate_client_config(&endpoint, &public_key, None)?;
        println!("{}", client_config);

        println!("\nSave the client config to a file and import into WireGuard app,");
        println!("or generate a QR code with: qrencode -t ansiutf8 < client.conf");

        return Ok(());
    }

    info!("Starting Oxidize Server v{}", env!("CARGO_PKG_VERSION"));
    info!("Listening on {}", args.listen);
    info!("╔════════════════════════════════════════╗");
    info!("║   Oxidize Server v0.1.0                ║");
    info!("╚════════════════════════════════════════╝");

    let config = Config::load(&args.config).unwrap_or_else(|_| {
        warn!("Config file not found, using defaults");
        Config::default()
    });

    let server = Arc::new(RelayServer::new(args.listen, config).await?);

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

        let prom_metrics = prometheus::PrometheusMetrics::new()?;
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

    // Start WireGuard server if enabled
    let config_ref = server.config();
    if config_ref.enable_wireguard {
        let wg_port = config_ref.wireguard_port.unwrap_or(51820);
        let wg_addr: SocketAddr = format!("0.0.0.0:{}", wg_port).parse()?;

        if let Some(ref private_key_b64) = config_ref.wireguard_private_key {
            use base64::{engine::general_purpose, Engine as _};
            let key_bytes = general_purpose::STANDARD.decode(private_key_b64)?;
            let mut private_key = [0u8; 32];
            private_key.copy_from_slice(&key_bytes);

            let wg_server = WireGuardServer::new(wg_addr, private_key).await?;
            info!("📱 WireGuard server listening on {}", wg_addr);

            tokio::spawn(async move {
                if let Err(e) = wg_server.run().await {
                    warn!("WireGuard server error: {}", e);
                }
            });
        } else {
            warn!("WireGuard enabled but no private key configured");
        }
    }

    server.run().await?;

    Ok(())
}
