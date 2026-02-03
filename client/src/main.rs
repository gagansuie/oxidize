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
mod speedtest;

use client::{ClientConfig as OxTunnelConfig, RelayClient};
use config::ClientConfig;
use dns_cache::DnsCache;
use oxidize_common::auth::ClientAuthConfig;
use speedtest::{SpeedTest, SpeedTestConfig};

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

    /// Run UDP ping/throughput speed test instead of starting the client
    #[arg(long)]
    speedtest: bool,

    /// Print speed test results as JSON
    #[arg(long)]
    speedtest_json: bool,

    /// Speed test packet size in bytes
    #[arg(long, default_value_t = 1400)]
    speedtest_packet_size: usize,

    /// Speed test packet count
    #[arg(long, default_value_t = 1000)]
    speedtest_packet_count: usize,

    /// Speed test warmup packets
    #[arg(long, default_value_t = 10)]
    speedtest_warmup_packets: usize,

    /// Print daemon status and exit
    #[arg(long)]
    daemon_status: bool,

    /// Install the daemon service and exit
    #[arg(long)]
    install_daemon: bool,

    /// Ensure daemon is running (install/start if needed) and exit
    #[arg(long)]
    ensure_daemon: bool,
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

    if args.daemon_status || args.install_daemon || args.ensure_daemon {
        if args.daemon_status {
            let running = daemon::is_daemon_running().await;
            if running {
                info!("✅ Daemon status: running");
            } else {
                warn!("⚠️  Daemon status: not running");
            }
        }

        if args.install_daemon {
            daemon::install_daemon()?;
        }

        if args.ensure_daemon {
            daemon::ensure_daemon_running().await?;
        }

        return Ok(());
    }

    info!("╔════════════════════════════════════════╗");
    info!("║   Oxidize Client (OxTunnel Protocol)   ║");
    info!("╚════════════════════════════════════════╝");

    let config = ClientConfig::load(&args.config).unwrap_or_else(|_| {
        info!("Config file not found, using defaults");
        ClientConfig::default()
    });

    let dns_cache = if config.enable_dns_prefetch {
        Some(DnsCache::new(config.dns_cache_size))
    } else {
        None
    };

    if args.speedtest {
        let server = args
            .server
            .ok_or_else(|| anyhow::anyhow!("Server address is required. Use --server <address>"))?;
        let server_addr = resolve_server_address(&server, dns_cache.as_ref()).await?;

        let test_config = SpeedTestConfig {
            server_addr,
            packet_size: args.speedtest_packet_size,
            packet_count: args.speedtest_packet_count,
            warmup_packets: args.speedtest_warmup_packets,
        };

        let speedtest = SpeedTest::with_config(test_config);
        let results = speedtest.run().await?;
        if args.speedtest_json {
            results.print_json()?;
        } else {
            results.print_human();
        }

        return Ok(());
    }

    // Server is required for running the client
    let server = args
        .server
        .ok_or_else(|| anyhow::anyhow!("Server address is required. Use --server <address>"))?;
    let server_addr: SocketAddr = resolve_server_address(&server, dns_cache.as_ref()).await?;

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
        // TCP fallback on port 51821 for restrictive networks
        tcp_fallback_addr: Some(std::net::SocketAddr::new(server_addr.ip(), 51821)),
        transport_mode: crate::client::TransportMode::Auto,
        enable_encryption: true,
        encryption_key: None,
        enable_compression: config.enable_compression,
        compression_threshold: config.compression_threshold,
        enable_rohc: config.enable_rohc,
        rohc_max_size: config.rohc_max_size,
        enable_ai_engine: config.enable_ai_engine,
        keepalive_interval: Duration::from_secs(config.keepalive_interval),
        connection_timeout: Duration::from_secs(30),
        auth_config,
    };

    let client = RelayClient::new(oxtunnel_config).await?;

    // Connect to server
    client.connect().await?;

    info!("🚀 OxTunnel client connected!");

    // Keep connection alive - packet capture handled by daemon via TUN
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
async fn resolve_server_address(server: &str, dns_cache: Option<&DnsCache>) -> Result<SocketAddr> {
    // First try parsing as a direct SocketAddr
    if let Ok(addr) = server.parse::<SocketAddr>() {
        return Ok(addr);
    }

    let mut cached_port = None;
    if let Some((host, port)) = split_host_port(server) {
        cached_port = Some((host, port));
    }

    if let (Some(cache), Some((host, port))) = (dns_cache, cached_port.as_ref()) {
        if let Some(ip) = cache.get(host).await {
            return Ok(SocketAddr::new(ip, *port));
        }
    }

    // Otherwise, resolve via DNS
    let addrs: Vec<SocketAddr> = lookup_host(server)
        .await
        .with_context(|| format!("Failed to resolve server address: {}", server))?
        .collect();

    let addr = addrs
        .into_iter()
        .next()
        .with_context(|| format!("No addresses found for: {}", server))?;

    if let (Some(cache), Some((host, _))) = (dns_cache, cached_port) {
        cache.insert(host, addr.ip(), None).await;
    }

    Ok(addr)
}

fn split_host_port(server: &str) -> Option<(String, u16)> {
    let (host, port_str) = server.rsplit_once(':')?;
    let host = host.trim();

    let host = if host.starts_with('[') && host.ends_with(']') && host.len() > 2 {
        &host[1..host.len() - 1]
    } else {
        host
    };

    let port = port_str.parse::<u16>().ok()?;
    Some((host.to_string(), port))
}
