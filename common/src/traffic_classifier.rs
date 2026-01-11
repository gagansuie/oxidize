//! Traffic Classification and Smart Routing
//!
//! Classifies network traffic to determine optimal routing:
//! - Gaming traffic → Through QUIC tunnel (low latency)
//! - Streaming traffic → Direct/bypass (user's residential IP)
//! - General traffic → Through tunnel (privacy)

use crate::low_latency::{is_gaming_port, is_voip_port};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Traffic classification result
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrafficClass {
    /// Gaming traffic - needs lowest latency
    Gaming,
    /// Streaming services - should bypass tunnel for residential IP
    Streaming,
    /// VoIP/Video calls - low latency, jitter sensitive
    RealTime,
    /// General web browsing
    Web,
    /// Bulk downloads/uploads
    Bulk,
    /// Unknown/default
    General,
}

impl TrafficClass {
    /// Should this traffic bypass the tunnel?
    pub fn should_bypass(&self) -> bool {
        matches!(self, TrafficClass::Streaming)
    }

    /// Priority for scheduling (higher = more important)
    pub fn priority(&self) -> u8 {
        match self {
            TrafficClass::Gaming => 255,
            TrafficClass::RealTime => 240,
            TrafficClass::Streaming => 200,
            TrafficClass::Web => 128,
            TrafficClass::General => 64,
            TrafficClass::Bulk => 32,
        }
    }
}

/// Configuration for traffic classification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierConfig {
    /// Domains to always bypass (streaming services)
    pub bypass_domains: Vec<String>,
    /// Domains to always tunnel (privacy-sensitive)
    pub force_tunnel_domains: Vec<String>,
    /// Gaming server IP ranges to prioritize
    pub gaming_ip_ranges: Vec<String>,
    /// Ports commonly used by games
    pub gaming_ports: Vec<u16>,
    /// Enable deep packet inspection for better classification
    pub enable_dpi: bool,
    /// Enable automatic streaming detection
    pub auto_detect_streaming: bool,
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            bypass_domains: vec![
                // Netflix
                "netflix.com".into(),
                "nflxvideo.net".into(),
                "nflximg.net".into(),
                "nflxext.com".into(),
                "nflxso.net".into(),
                // Disney+
                "disneyplus.com".into(),
                "disney-plus.net".into(),
                "dssott.com".into(),
                "bamgrid.com".into(),
                // Hulu
                "hulu.com".into(),
                "hulustream.com".into(),
                // Amazon Prime
                "primevideo.com".into(),
                "amazonvideo.com".into(),
                "aiv-cdn.net".into(),
                // HBO Max
                "max.com".into(),
                "hbomax.com".into(),
                // YouTube (optional - usually works through datacenter)
                // "youtube.com".into(),
                // "googlevideo.com".into(),
                // Paramount+
                "paramountplus.com".into(),
                // Peacock
                "peacocktv.com".into(),
                // Apple TV+
                "apple.com".into(),
                "tv.apple.com".into(),
                // Spotify (audio streaming)
                "spotify.com".into(),
                "scdn.co".into(),
                // IDE/Dev tools (prevent breaking AI assistants)
                "codeium.com".into(),
                "windsurf.ai".into(),
                "cursor.sh".into(),
                "cursor.so".into(),
                "copilot.github.com".into(),
                "githubcopilot.com".into(),
                "tabnine.com".into(),
                // Cloud databases (connection stability)
                "mongodb.net".into(),
                "mongodb.com".into(),
                "supabase.co".into(),
                "supabase.com".into(),
                "planetscale.com".into(),
                "firebaseio.com".into(),
                // Cloud provider consoles/APIs
                "aws.amazon.com".into(),
                "amazonaws.com".into(),
                "cloud.google.com".into(),
                "googleapis.com".into(),
                "azure.com".into(),
            ],
            force_tunnel_domains: vec![
                // Privacy-sensitive - always tunnel
                "protonmail.com".into(),
                "signal.org".into(),
            ],
            gaming_ip_ranges: vec![
                // Riot Games
                "104.160.0.0/16".into(),
                // Valve/Steam
                "208.64.200.0/22".into(),
                "185.25.180.0/22".into(),
                // Epic Games
                "99.83.136.0/24".into(),
                // Activision
                "24.105.0.0/16".into(),
            ],
            gaming_ports: vec![
                // Common game server ports
                27015, 27016, 27017, // Source engine
                7777, 7778, 7779, // Unreal engine
                3074, // Xbox Live
                3478, 3479, 3480, // PlayStation
                5060, 5061, 5062, // Riot Games
                6672, 6673, // EA
                9000, 9001, 9002, // Various games
            ],
            enable_dpi: false,
            auto_detect_streaming: true,
        }
    }
}

/// Traffic classifier
#[allow(dead_code)]
pub struct TrafficClassifier {
    config: ClassifierConfig,
    /// Cached domain -> bypass decisions
    domain_cache: Arc<RwLock<HashSet<String>>>,
    /// Known streaming IPs (learned over time)
    streaming_ips: Arc<RwLock<HashSet<IpAddr>>>,
    /// Known gaming IPs (learned over time)  
    gaming_ips: Arc<RwLock<HashSet<IpAddr>>>,
}

impl TrafficClassifier {
    /// Create a new traffic classifier
    pub fn new(config: ClassifierConfig) -> Self {
        Self {
            config,
            domain_cache: Arc::new(RwLock::new(HashSet::new())),
            streaming_ips: Arc::new(RwLock::new(HashSet::new())),
            gaming_ips: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Classify a packet based on destination
    pub async fn classify(
        &self,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: Protocol,
        domain: Option<&str>,
    ) -> TrafficClass {
        // Check domain-based rules first
        if let Some(domain) = domain {
            if self.is_bypass_domain(domain) {
                return TrafficClass::Streaming;
            }
            if self.is_force_tunnel_domain(domain) {
                return TrafficClass::General;
            }
        }

        // Check gaming ports (config + low_latency detection)
        if self.config.gaming_ports.contains(&dest_port) || is_gaming_port(dest_port) {
            return TrafficClass::Gaming;
        }

        // Check VoIP ports
        if is_voip_port(dest_port) {
            return TrafficClass::RealTime;
        }

        // Check known gaming IPs
        if self.gaming_ips.read().await.contains(&dest_ip) {
            return TrafficClass::Gaming;
        }

        // Check known streaming IPs
        if self.streaming_ips.read().await.contains(&dest_ip) {
            return TrafficClass::Streaming;
        }

        // Protocol-based heuristics
        match protocol {
            Protocol::Udp => {
                // UDP on high ports often gaming
                if dest_port > 10000 {
                    TrafficClass::Gaming
                } else {
                    TrafficClass::General
                }
            }
            Protocol::Tcp => {
                // HTTPS
                if dest_port == 443 || dest_port == 80 {
                    TrafficClass::Web
                } else {
                    TrafficClass::General
                }
            }
        }
    }

    /// Check if domain should bypass tunnel
    pub fn is_bypass_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.config
            .bypass_domains
            .iter()
            .any(|bypass| domain_lower.ends_with(bypass) || domain_lower == *bypass)
    }

    /// Check if domain should always be tunneled
    pub fn is_force_tunnel_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.config
            .force_tunnel_domains
            .iter()
            .any(|force| domain_lower.ends_with(force) || domain_lower == *force)
    }

    /// Learn that an IP is used for streaming
    pub async fn learn_streaming_ip(&self, ip: IpAddr) {
        self.streaming_ips.write().await.insert(ip);
    }

    /// Learn that an IP is used for gaming
    pub async fn learn_gaming_ip(&self, ip: IpAddr) {
        self.gaming_ips.write().await.insert(ip);
    }

    /// Get routing decision for a packet
    pub async fn get_route(
        &self,
        dest_ip: IpAddr,
        dest_port: u16,
        protocol: Protocol,
        domain: Option<&str>,
    ) -> RouteDecision {
        let class = self.classify(dest_ip, dest_port, protocol, domain).await;

        RouteDecision {
            class,
            bypass_tunnel: class.should_bypass(),
            priority: class.priority(),
        }
    }

    /// Check if destination should bypass tunnel (quick check for TUN handler)
    pub fn should_bypass_ip(&self, _dest_ip: IpAddr, dest_port: u16) -> bool {
        // Quick synchronous check for hot path
        // More thorough async check can be done separately

        // Known streaming ports
        if dest_port == 443 {
            // Could be streaming, need domain check
            // For now, don't bypass unknown HTTPS
            return false;
        }

        false
    }

    /// Add a domain to bypass list dynamically
    pub fn add_bypass_domain(&mut self, domain: String) {
        if !self.config.bypass_domains.contains(&domain) {
            self.config.bypass_domains.push(domain);
        }
    }

    /// Remove a domain from bypass list
    pub fn remove_bypass_domain(&mut self, domain: &str) {
        self.config.bypass_domains.retain(|d| d != domain);
    }

    /// Get current bypass domains
    pub fn bypass_domains(&self) -> &[String] {
        &self.config.bypass_domains
    }
}

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl From<u8> for Protocol {
    fn from(proto: u8) -> Self {
        match proto {
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => Protocol::Tcp, // Default to TCP for unknown
        }
    }
}

/// Routing decision
#[derive(Debug, Clone)]
pub struct RouteDecision {
    /// Traffic classification
    pub class: TrafficClass,
    /// Should bypass the tunnel
    pub bypass_tunnel: bool,
    /// Priority (0-255)
    pub priority: u8,
}

/// DNS-based traffic detection
pub struct DnsTrafficDetector {
    /// Domain -> IP mappings from DNS responses
    domain_ips: Arc<RwLock<std::collections::HashMap<IpAddr, String>>>,
}

impl DnsTrafficDetector {
    pub fn new() -> Self {
        Self {
            domain_ips: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Record a DNS resolution
    pub async fn record_dns(&self, domain: String, ips: Vec<IpAddr>) {
        let mut map = self.domain_ips.write().await;
        for ip in ips {
            map.insert(ip, domain.clone());
        }

        // Limit cache size
        if map.len() > 10000 {
            // Remove oldest entries (simple approach: clear half)
            let to_remove: Vec<_> = map.keys().take(5000).copied().collect();
            for ip in to_remove {
                map.remove(&ip);
            }
        }
    }

    /// Look up domain for an IP
    pub async fn get_domain(&self, ip: IpAddr) -> Option<String> {
        self.domain_ips.read().await.get(&ip).cloned()
    }
}

impl Default for DnsTrafficDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ClassifierConfig::default();
        assert!(!config.bypass_domains.is_empty());
        assert!(config.bypass_domains.iter().any(|d| d.contains("netflix")));
    }

    #[test]
    fn test_bypass_domain_check() {
        let config = ClassifierConfig::default();
        let classifier = TrafficClassifier::new(config);

        assert!(classifier.is_bypass_domain("www.netflix.com"));
        assert!(classifier.is_bypass_domain("api.netflix.com"));
        assert!(classifier.is_bypass_domain("netflix.com"));
        assert!(!classifier.is_bypass_domain("google.com"));
    }

    #[test]
    fn test_traffic_class_priority() {
        assert!(TrafficClass::Gaming.priority() > TrafficClass::Streaming.priority());
        assert!(TrafficClass::Streaming.priority() > TrafficClass::Web.priority());
        assert!(TrafficClass::Web.priority() > TrafficClass::Bulk.priority());
    }

    #[test]
    fn test_should_bypass() {
        assert!(TrafficClass::Streaming.should_bypass());
        assert!(!TrafficClass::Gaming.should_bypass());
        assert!(!TrafficClass::Web.should_bypass());
    }

    #[tokio::test]
    async fn test_classify_gaming_port() {
        let classifier = TrafficClassifier::new(ClassifierConfig::default());
        let class = classifier
            .classify(
                "1.2.3.4".parse().unwrap(),
                27015, // Source engine
                Protocol::Udp,
                None,
            )
            .await;
        assert_eq!(class, TrafficClass::Gaming);
    }

    #[tokio::test]
    async fn test_classify_streaming_domain() {
        let classifier = TrafficClassifier::new(ClassifierConfig::default());
        let class = classifier
            .classify(
                "1.2.3.4".parse().unwrap(),
                443,
                Protocol::Tcp,
                Some("www.netflix.com"),
            )
            .await;
        assert_eq!(class, TrafficClass::Streaming);
    }

    #[tokio::test]
    async fn test_dns_detector() {
        let detector = DnsTrafficDetector::new();

        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        detector
            .record_dns("netflix.com".to_string(), vec![ip])
            .await;

        let domain = detector.get_domain(ip).await;
        assert_eq!(domain, Some("netflix.com".to_string()));
    }

    #[tokio::test]
    async fn test_route_decision() {
        let classifier = TrafficClassifier::new(ClassifierConfig::default());

        // Netflix should bypass
        let decision = classifier
            .get_route(
                "1.2.3.4".parse().unwrap(),
                443,
                Protocol::Tcp,
                Some("netflix.com"),
            )
            .await;
        assert!(decision.bypass_tunnel);

        // Gaming should not bypass
        let decision = classifier
            .get_route("1.2.3.4".parse().unwrap(), 27015, Protocol::Udp, None)
            .await;
        assert!(!decision.bypass_tunnel);
    }
}
