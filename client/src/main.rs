use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::lookup_host;
use tracing::info;

mod client;
mod config;
mod dns_cache;
mod speedtest;
mod xdp_handler;

use client::RelayClient;
use config::ClientConfig;
use speedtest::SpeedTest;

#[derive(Parser, Debug)]
#[command(name = "oxidize-client")]
#[command(about = "Oxidize - High-performance Network Relay Client", long_about = None)]
struct Args {
    #[arg(short, long)]
    server: Option<String>,

    #[arg(short, long, default_value = "/etc/oxidize/client.toml")]
    config: String,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long)]
    no_xdp: bool,

    /// Run a speed test comparing direct vs relay connection
    #[arg(long)]
    speedtest: bool,

    /// Output speed test results as JSON
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Manage bypass domains (domains not routed through tunnel)
    Bypass {
        #[command(subcommand)]
        action: BypassAction,
    },
}

#[derive(Subcommand, Debug)]
enum BypassAction {
    /// Add a domain to bypass list
    Add {
        /// Domain to bypass (e.g., "example.com")
        domain: String,
    },
    /// Remove a domain from bypass list
    Remove {
        /// Domain to remove from bypass list
        domain: String,
    },
    /// List all configured bypass domains
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle bypass subcommand first (no logging needed)
    if let Some(Command::Bypass { action }) = args.command {
        return handle_bypass_command(action, &args.config);
    }

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

    info!("Oxidize Client starting...");

    let config = ClientConfig::load(&args.config).unwrap_or_else(|_| {
        info!("Config file not found, using defaults");
        ClientConfig::default()
    });

    // Server is required for running the client
    let server = args
        .server
        .ok_or_else(|| anyhow::anyhow!("Server address is required. Use --server <address>"))?;
    let server_addr: SocketAddr = resolve_server_address(&server).await?;

    // Run speed test if requested
    if args.speedtest {
        let speedtest = SpeedTest::new(server_addr);
        let results = speedtest.run().await?;

        if args.json {
            results.print_json()?;
        } else {
            results.print_human();
        }
        return Ok(());
    }

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

    if !args.no_xdp {
        info!("🚀 Starting AF_XDP high-performance mode (10+ Gbps)...");
        client.run_with_xdp().await?;
    } else {
        info!("⚙️  Running in proxy mode (no packet capture)...");
        client.run().await?;
    }

    Ok(())
}

fn handle_bypass_command(action: BypassAction, config_path: &str) -> Result<()> {
    use oxidize_common::traffic_classifier::ClassifierConfig;
    use std::path::Path;

    // Load or create config
    let mut config = if Path::new(config_path).exists() {
        ClientConfig::load(config_path).unwrap_or_default()
    } else {
        ClientConfig::default()
    };

    // Get default bypass domains for reference
    let default_config = ClassifierConfig::default();
    let default_domains = default_config.bypass_domains;

    match action {
        BypassAction::Add { domain } => {
            let domain = domain.to_lowercase();
            if config.bypass_domains.contains(&domain) {
                println!("Domain '{}' is already in bypass list", domain);
            } else if default_domains.iter().any(|d| d == &domain) {
                println!("Domain '{}' is already bypassed by default", domain);
            } else {
                config.bypass_domains.push(domain.clone());
                save_config(&config, config_path)?;
                println!("Added '{}' to bypass list", domain);
            }
        }
        BypassAction::Remove { domain } => {
            let domain = domain.to_lowercase();
            if let Some(pos) = config.bypass_domains.iter().position(|d| d == &domain) {
                config.bypass_domains.remove(pos);
                save_config(&config, config_path)?;
                println!("Removed '{}' from bypass list", domain);
            } else if default_domains.iter().any(|d| d == &domain) {
                println!("Cannot remove '{}' - it's a built-in default. Use force_tunnel_domains to override.", domain);
            } else {
                println!("Domain '{}' not found in bypass list", domain);
            }
        }
        BypassAction::List => {
            println!("=== Default Bypass Domains (built-in) ===");
            for domain in &default_domains {
                println!("  {}", domain);
            }
            println!("\n=== Custom Bypass Domains (from config) ===");
            if config.bypass_domains.is_empty() {
                println!("  (none)");
            } else {
                for domain in &config.bypass_domains {
                    println!("  {}", domain);
                }
            }
            println!("\nConfig file: {}", config_path);
        }
    }

    Ok(())
}

fn save_config(config: &ClientConfig, path: &str) -> Result<()> {
    use std::fs;
    use std::path::Path;

    // Ensure parent directory exists
    if let Some(parent) = Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }

    let content = toml::to_string_pretty(config)?;
    fs::write(path, content)?;
    Ok(())
}

/// Resolve a server address that can be either:
/// - A direct SocketAddr like "1.2.3.4:4433"
/// - A hostname:port like "relay.oxd.sh:4433"
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
