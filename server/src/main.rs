use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

mod cache;
mod config;
mod connection;
mod prometheus;
mod rate_limiter;
mod server;
mod tls;

use config::Config;
use server::RelayServer;

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

    server.run().await?;

    Ok(())
}
