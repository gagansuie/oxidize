use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;

mod client;
mod config;
mod dns_cache;
mod tun_handler;

use client::RelayClient;
use config::ClientConfig;

#[derive(Parser, Debug)]
#[command(name = "relay-client")]
#[command(about = "Oxidize - High-performance Network Relay Client", long_about = None)]
struct Args {
    #[arg(short, long)]
    server: String,

    #[arg(short, long, default_value = "config.toml")]
    config: String,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long)]
    no_tun: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if args.verbose {
        "oxidize_client=trace,oxidize_common=debug"
    } else {
        "oxidize_client=info,oxidize_common=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!("╔════════════════════════════════════════╗");
    info!("║   Oxidize Client v0.1.0                ║");
    info!("╚════════════════════════════════════════╝");

    let config = ClientConfig::load(&args.config).unwrap_or_else(|_| {
        info!("Config file not found, using defaults");
        ClientConfig::default()
    });

    let server_addr: SocketAddr = args.server.parse()?;

    info!("🔗 Connecting to relay server: {}", server_addr);
    info!(
        "🗜️  Compression: {}",
        if config.enable_compression {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!(
        "📡 DNS prefetching: {}",
        if config.enable_dns_prefetch {
            "enabled"
        } else {
            "disabled"
        }
    );

    let client = Arc::new(RelayClient::new(server_addr, config).await?);

    let stats_client = client.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            let stats = stats_client.get_metrics().get_stats();
            stats.print_summary();
        }
    });

    if !args.no_tun {
        info!("🌐 Starting TUN interface...");
        client.run_with_tun().await?;
    } else {
        info!("⚙️  Running in proxy mode (no TUN)...");
        client.run().await?;
    }

    Ok(())
}
