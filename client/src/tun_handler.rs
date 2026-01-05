use anyhow::{Context, Result};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::config::ClientConfig;

pub struct TunHandler {
    config: ClientConfig,
}

impl TunHandler {
    pub fn new(config: ClientConfig) -> Result<Self> {
        Ok(Self { config })
    }

    pub async fn run(&self, tx: mpsc::Sender<Vec<u8>>) -> Result<()> {
        info!("Setting up TUN interface...");

        let mut tun_config = tun::Configuration::default();
        tun_config
            .address((10, 0, 0, 1))
            .netmask((255, 255, 255, 0))
            .mtu(self.config.tun_mtu as i32)
            .up();

        #[cfg(target_os = "linux")]
        tun_config.platform(|config| {
            config.packet_information(false);
        });

        let mut dev = tun::create(&tun_config)
            .context("Failed to create TUN device. You may need root/admin privileges.")?;

        info!("✅ TUN interface created");
        info!("   Address: 10.0.0.1/24");
        info!("   MTU: {}", self.config.tun_mtu);

        let mtu = self.config.tun_mtu;

        tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut buffer = vec![0u8; mtu + 4];

            loop {
                match dev.read(&mut buffer) {
                    Ok(len) => {
                        debug!("Received {} bytes from TUN", len);

                        let packet = buffer[..len].to_vec();

                        if tx.blocking_send(packet).is_err() {
                            error!("Failed to queue packet");
                            break;
                        }
                    }
                    Err(e) => {
                        error!("TUN read error: {}", e);
                        break;
                    }
                }
            }
        })
        .await?;

        Ok(())
    }
}
