use anyhow::{Context, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::lookup_host;
use tracing::{info, warn};

mod client;
mod config;
mod daemon;
mod dns_cache;

use client::{ClientConfig as OxTunnelConfig, RelayClient};
use config::ClientConfig;
use oxidize_common::auth::ClientAuthConfig;

#[derive(Parser, Debug)]
#[command(name = "oxidize-client")]
#[command(about = "Oxidize - High-performance OxTunnel Client", long_about = None)]
struct Args {
    #[arg(short, long)]
    server: Option<String>,

    #[arg(short, long, default_value = "/etc/oxidize/client.toml")]
    config: String,

    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter = if args.verbose {
        "relay_client=trace,oxidize_common=debug"
    } else {
        "relay_client=info,oxidize_common=info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!("╔════════════════════════════════════════╗");
    info!("║   Oxidize Client (OxTunnel Protocol)   ║");
    info!("╚════════════════════════════════════════╝");

    let config = ClientConfig::load(&args.config).unwrap_or_else(|_| {
        info!("Config file not found, using defaults");
        ClientConfig::default()
    });

    // Server is required for running the client
    let server = args
        .server
        .ok_or_else(|| anyhow::anyhow!("Server address is required. Use --server <address>"))?;
    let server_addr: SocketAddr = resolve_server_address(&server).await?;

    info!("🔗 Connecting to OxTunnel server: {}", server_addr);
    info!(
        "🗜️  Compression: {}",
        if config.enable_compression {
            "enabled"
        } else {
            "disabled"
        }
    );

    // Load auth config from environment if available
    let auth_config = ClientAuthConfig::from_env();
    if auth_config.is_some() {
        info!("🔐 Authentication ENABLED (loaded from environment)");
    } else {
        warn!("⚠️  Authentication DISABLED - set OXIDIZE_APP_SIGNING_KEY, OXIDIZE_API_KEY, OXIDIZE_API_SECRET");
    }

    // Create OxTunnel client config
    let oxtunnel_config = OxTunnelConfig {
        server_addr,
        enable_encryption: true,
        encryption_key: None,
        enable_compression: config.enable_compression,
        keepalive_interval: Duration::from_secs(config.keepalive_interval),
        connection_timeout: Duration::from_secs(30),
        #[cfg(target_os = "linux")]
        xdp_interface: None, // Auto-detect or use optimized UDP
        auth_config,
    };

    let client = RelayClient::new(oxtunnel_config).await?;

    // Connect to server
    client.connect().await?;

    info!("🚀 OxTunnel client connected!");

    // For now, just keep the connection alive
    // TODO: Integrate with daemon packet capture
    loop {
        tokio::time::sleep(Duration::from_secs(10)).await;
        if !client.is_connected() {
            warn!("Connection lost, attempting reconnect...");
            if let Err(e) = client.connect().await {
                warn!("Reconnect failed: {}", e);
            }
        }
    }
}

/// Resolve a server address that can be either:
/// - A direct SocketAddr like "1.2.3.4:51820"
/// - A hostname:port like "relay-chi-1.example.com:51820"
async fn resolve_server_address(server: &str) -> Result<SocketAddr> {
    // First try parsing as a direct SocketAddr
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(addr);
    }

    // Otherwise, resolve via DNS
    let addrs: Vec<SocketAddr> = lookup_host(server)
        .await
        .with_context(|| format!("Failed to resolve server address: {}", server))?
        .collect();

    addrs
        .into_iter()
        .next()
        .with_context(|| format!("No addresses found for: {}", server))
}
