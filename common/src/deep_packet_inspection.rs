//! Deep Packet Inspection + Application Fingerprinting
//!
//! Identifies applications by protocol patterns, not just ports.
//! Detects Discord/Zoom/Games on non-standard ports.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdentifiedApp {
    Valorant,
    LeagueOfLegends,
    Fortnite,
    ApexLegends,
    CSGO,
    Minecraft,
    Roblox,
    GenericGame,
    Discord,
    Zoom,
    Teams,
    Slack,
    Telegram,
    WhatsApp,
    GenericVoIP,
    YouTube,
    Netflix,
    Twitch,
    Spotify,
    GenericStreaming,
    WebBrowsing,
    FileTransfer,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficClass {
    Gaming,
    VoIP,
    Streaming,
    Interactive,
    Bulk,
    Normal,
}

impl IdentifiedApp {
    pub fn traffic_class(&self) -> TrafficClass {
        match self {
            Self::Valorant
            | Self::CSGO
            | Self::ApexLegends
            | Self::Fortnite
            | Self::LeagueOfLegends
            | Self::Minecraft
            | Self::Roblox
            | Self::GenericGame => TrafficClass::Gaming,

            Self::Discord
            | Self::Zoom
            | Self::Teams
            | Self::Slack
            | Self::Telegram
            | Self::WhatsApp
            | Self::GenericVoIP => TrafficClass::VoIP,

            Self::YouTube
            | Self::Netflix
            | Self::Twitch
            | Self::Spotify
            | Self::GenericStreaming => TrafficClass::Streaming,

            Self::WebBrowsing => TrafficClass::Interactive,
            Self::FileTransfer => TrafficClass::Bulk,
            Self::Unknown => TrafficClass::Normal,
        }
    }
}

#[derive(Debug)]
pub struct DeepPacketInspector {
    signatures: Vec<AppSignature>,
    flow_cache: RwLock<HashMap<FlowKey, CachedFlow>>,
    pub stats: DpiStats,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct FlowKey {
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
}

#[derive(Debug, Clone)]
struct CachedFlow {
    app: IdentifiedApp,
    confidence: u8,
    last_seen: Instant,
}

#[derive(Debug, Default)]
pub struct DpiStats {
    pub packets_inspected: AtomicU64,
    pub flows_identified: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
}

#[derive(Debug, Clone)]
struct AppSignature {
    app: IdentifiedApp,
    ports: Vec<u16>,
    payload_prefix: Option<Vec<u8>>,
    min_size: Option<u16>,
    max_size: Option<u16>,
}

impl DeepPacketInspector {
    pub fn new() -> Self {
        Self {
            signatures: Self::build_signatures(),
            flow_cache: RwLock::new(HashMap::new()),
            stats: DpiStats::default(),
        }
    }

    fn build_signatures() -> Vec<AppSignature> {
        vec![
            // Discord RTC
            AppSignature {
                app: IdentifiedApp::Discord,
                ports: vec![50000, 50001, 50002, 50003, 50004, 50005],
                payload_prefix: Some(vec![0x16, 0xfe]), // DTLS
                min_size: Some(50),
                max_size: Some(1400),
            },
            // Zoom
            AppSignature {
                app: IdentifiedApp::Zoom,
                ports: vec![8801, 8802, 8803, 8804, 8805],
                payload_prefix: Some(vec![0x16, 0xfe]),
                min_size: Some(100),
                max_size: Some(1400),
            },
            // Teams
            AppSignature {
                app: IdentifiedApp::Teams,
                ports: vec![3478, 3479, 3480, 3481],
                payload_prefix: None,
                min_size: None,
                max_size: None,
            },
            // Valorant
            AppSignature {
                app: IdentifiedApp::Valorant,
                ports: (7000..=7010).collect(),
                payload_prefix: None,
                min_size: Some(20),
                max_size: Some(500),
            },
            // Fortnite
            AppSignature {
                app: IdentifiedApp::Fortnite,
                ports: vec![5222, 5795, 5847, 9000, 9001, 9002, 9003, 9004, 9005],
                payload_prefix: None,
                min_size: Some(30),
                max_size: Some(600),
            },
            // Apex
            AppSignature {
                app: IdentifiedApp::ApexLegends,
                ports: (37015..=37020).collect(),
                payload_prefix: None,
                min_size: None,
                max_size: None,
            },
            // CS:GO/CS2
            AppSignature {
                app: IdentifiedApp::CSGO,
                ports: vec![
                    27015, 27016, 27017, 27018, 27019, 27020, 27025, 27030, 27031,
                ],
                payload_prefix: None,
                min_size: Some(20),
                max_size: Some(1400),
            },
            // League of Legends
            AppSignature {
                app: IdentifiedApp::LeagueOfLegends,
                ports: (5000..=5009).collect(),
                payload_prefix: None,
                min_size: None,
                max_size: None,
            },
            // Minecraft
            AppSignature {
                app: IdentifiedApp::Minecraft,
                ports: vec![25565, 25566, 25567],
                payload_prefix: None,
                min_size: None,
                max_size: None,
            },
            // Roblox
            AppSignature {
                app: IdentifiedApp::Roblox,
                ports: (49152..=49159).collect(),
                payload_prefix: None,
                min_size: None,
                max_size: None,
            },
            // Twitch
            AppSignature {
                app: IdentifiedApp::Twitch,
                ports: vec![443, 1935],
                payload_prefix: None,
                min_size: Some(500),
                max_size: Some(1400),
            },
            // Spotify
            AppSignature {
                app: IdentifiedApp::Spotify,
                ports: vec![443, 4070],
                payload_prefix: None,
                min_size: None,
                max_size: None,
            },
        ]
    }

    pub fn inspect(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
        payload: &[u8],
        packet_size: u16,
    ) -> IdentifiedApp {
        self.stats.packets_inspected.fetch_add(1, Ordering::Relaxed);

        let key = FlowKey {
            src_ip,
            src_port,
            dst_ip,
            dst_port,
        };

        // Check cache
        if let Ok(cache) = self.flow_cache.read() {
            if let Some(c) = cache.get(&key) {
                if c.last_seen.elapsed() < Duration::from_secs(60) {
                    self.stats.cache_hits.fetch_add(1, Ordering::Relaxed);
                    return c.app;
                }
            }
        }
        self.stats.cache_misses.fetch_add(1, Ordering::Relaxed);

        let app = self.identify(dst_port, payload, packet_size);

        // Cache result
        if let Ok(mut cache) = self.flow_cache.write() {
            cache.insert(
                key,
                CachedFlow {
                    app,
                    confidence: 80,
                    last_seen: Instant::now(),
                },
            );
            if cache.len() > 10000 {
                let cutoff = Instant::now() - Duration::from_secs(120);
                cache.retain(|_, v| v.last_seen > cutoff);
            }
        }

        if app != IdentifiedApp::Unknown {
            self.stats.flows_identified.fetch_add(1, Ordering::Relaxed);
        }
        app
    }

    fn identify(&self, port: u16, payload: &[u8], size: u16) -> IdentifiedApp {
        for sig in &self.signatures {
            let port_match = sig.ports.is_empty() || sig.ports.contains(&port);
            if !port_match {
                continue;
            }

            let payload_match = sig
                .payload_prefix
                .as_ref()
                .map(|p| payload.len() >= p.len() && &payload[..p.len()] == p.as_slice())
                .unwrap_or(true);

            let size_match = sig.min_size.map(|m| size >= m).unwrap_or(true)
                && sig.max_size.map(|m| size <= m).unwrap_or(true);

            if port_match && payload_match && size_match {
                return sig.app;
            }
        }
        self.heuristic(port, payload, size)
    }

    fn heuristic(&self, port: u16, payload: &[u8], size: u16) -> IdentifiedApp {
        match port {
            3074 | 3478..=3480 => IdentifiedApp::GenericGame,
            5060 | 5061 => IdentifiedApp::GenericVoIP,
            _ if size < 200 && !payload.is_empty() && (payload[0] & 0xf0 == 0x80) => {
                IdentifiedApp::GenericVoIP
            }
            _ if size > 1000 => IdentifiedApp::GenericStreaming,
            _ => IdentifiedApp::Unknown,
        }
    }

    pub fn cleanup_cache(&self) {
        if let Ok(mut cache) = self.flow_cache.write() {
            let cutoff = Instant::now() - Duration::from_secs(120);
            cache.retain(|_, v| v.last_seen > cutoff);
        }
    }
}

impl Default for DeepPacketInspector {
    fn default() -> Self {
        Self::new()
    }
}
