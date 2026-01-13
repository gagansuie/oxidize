# Security & DDoS Protection Guide

Oxidize is designed to be resilient against attacks. This guide covers security features and hardening recommendations.

## Is Oxidize a VPN?

**Functionally similar, but not identical:**

| Capability | Traditional VPN | Oxidize |
|------------|-----------------|---------|
| Encrypts traffic | ✅ TLS/IPsec | ✅ TLS 1.3 + QUIC |
| Hides client IP | ✅ | ✅ (relay IP visible) |
| Tunnels traffic | ✅ All system traffic | ✅ All UDP via NFQUEUE |
| Kernel integration | ✅ tun/tap device | ✅ NFQUEUE (userspace processing) |
| Protocol | OpenVPN/WireGuard/IPsec | QUIC |

**Key difference:** Oxidize uses NFQUEUE to intercept all UDP traffic in userspace, then forwards it through an encrypted QUIC tunnel. No kernel modules required.

---

## Built-in Security Features

### 1. QUIC Protocol Advantages

QUIC provides inherent DDoS resistance:

```
✅ Connection ID (not IP-based) - harder to spoof
✅ Encrypted headers - can't inspect/modify
✅ Stateless retry tokens - SYN flood protection
✅ Address validation - prevents IP spoofing
✅ Amplification limits - small responses to unverified clients
```

### 2. TLS 1.3 Encryption

All traffic is encrypted with TLS 1.3:
- Perfect forward secrecy
- No downgrade attacks
- Fast handshakes (0-RTT resumption when enabled)

### 3. 0-RTT Security Considerations

0-RTT session resumption is **disabled by default** for security:

```toml
# Client config
enable_0rtt = false  # Default: disabled for security

# Server config  
enable_0rtt = false  # Default: disabled
max_early_data_size = 16384  # 16KB when enabled
```

**Why 0-RTT is disabled by default:**
- 0-RTT data is vulnerable to **replay attacks**
- An attacker can capture and re-send 0-RTT data
- For VPN tunnels, this is usually safe (inner protocols have replay protection)
- Enable only if you understand the risks and need lowest latency

**When to enable 0-RTT:**
- Gaming/VoIP where latency is critical
- When inner protocols (TCP, game protocols) handle replay protection
- When you trust your network path

### 4. Rate Limiting

Per-IP connection and packet limits:

```toml
# config.toml
[security]
max_connections_per_ip = 100
max_pps_per_ip = 1000
max_bandwidth_per_ip = 10485760  # 10 MB/s
rate_limit_window_secs = 60
auto_block_threshold = 10  # Violations before auto-block
```

### 5. Security Manager

```rust
use oxidize_common::security::{SecurityManager, SecurityConfig};

let config = SecurityConfig {
    max_connections_per_ip: 100,
    max_pps_per_ip: 1000,
    enable_stateless_retry: true,
    enable_challenges: true,
    auto_block_threshold: 10,
    ..Default::default()
};

let mut security = SecurityManager::new(config);

// Check each connection
match security.check_connection(client_ip) {
    SecurityAction::Allow => { /* proceed */ }
    SecurityAction::RateLimit => { /* drop silently */ }
    SecurityAction::Challenge => { /* send QUIC retry */ }
    SecurityAction::Block => { /* reject */ }
    SecurityAction::Throttle => { /* slow down */ }
}
```

---

## DDoS Attack Mitigation

### Attack Types & Defenses

| Attack Type | Defense | Status |
|-------------|---------|--------|
| **SYN Flood** | QUIC stateless retry | ✅ Built-in |
| **UDP Flood** | Rate limiting per IP | ✅ Built-in |
| **Amplification** | Small initial responses | ✅ QUIC default |
| **Slowloris** | Connection timeouts | ✅ Built-in |
| **Application Layer** | Request validation | ✅ Built-in |
| **Volumetric** | Upstream filtering | ⚠️ Infrastructure |

### Layer 3/4 Protection (Infrastructure)

For volumetric attacks, use upstream protection:

```bash
# Fly.io - Built-in DDoS protection
# Included with Fly.io infrastructure

# Cloudflare Spectrum (paid)
# Proxies UDP/TCP through Cloudflare's network

# AWS Shield
# Available for AWS deployments
```

### Layer 7 Protection (Application)

```rust
// Packet validation
use oxidize_common::security::validate_packet;

if !validate_packet(&packet_data) {
    // Drop malformed packet
    continue;
}

// Check security manager
let action = security.check_packet(client_ip, packet_data.len());
if action != SecurityAction::Allow {
    continue;
}
```

---

## Hardening Checklist

### Server Configuration

```toml
# config.toml - Production hardened

[server]
listen = "0.0.0.0:4433"
max_connections = 10000
idle_timeout_secs = 30

[security]
# Rate limiting
max_connections_per_ip = 50
max_pps_per_ip = 500
max_bandwidth_per_ip = 5242880  # 5 MB/s
rate_limit_window_secs = 60

# Auto-blocking
auto_block_threshold = 5
blocklist_ttl_secs = 3600  # 1 hour

# QUIC security
enable_stateless_retry = true
enable_challenges = true
require_address_validation = true

# TLS
min_tls_version = "1.3"
certificate_path = "/etc/oxidize/cert.pem"
key_path = "/etc/oxidize/key.pem"

[limits]
# Resource limits
max_streams_per_connection = 100
max_data_per_stream = 10485760  # 10 MB
max_idle_timeout = 30
```

### Operating System Hardening

```bash
# /etc/sysctl.d/99-oxidize.conf

# Increase connection tracking
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600

# UDP buffer sizes
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.core.rmem_default = 16777216
net.core.wmem_default = 16777216

# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# SYN flood protection (for any TCP services)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 65536

# Apply
sudo sysctl -p /etc/sysctl.d/99-oxidize.conf
```

### Firewall Rules

```bash
# iptables rules for oxidize server

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Rate limit new UDP connections per IP
iptables -A INPUT -p udp --dport 4433 -m state --state NEW \
    -m recent --set --name OXIDIZE
iptables -A INPUT -p udp --dport 4433 -m state --state NEW \
    -m recent --update --seconds 1 --hitcount 20 --name OXIDIZE \
    -j DROP

# Allow Oxidize traffic
iptables -A INPUT -p udp --dport 4433 -j ACCEPT

# Drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# Limit ICMP
iptables -A INPUT -p icmp --icmp-type echo-request \
    -m limit --limit 1/s --limit-burst 4 -j ACCEPT
iptables -A INPUT -p icmp -j DROP
```

### nftables Alternative

```bash
# /etc/nftables.conf
table inet oxidize {
    set blocklist {
        type ipv4_addr
        flags timeout
    }
    
    chain input {
        type filter hook input priority 0; policy drop;
        
        # Drop blocked IPs
        ip saddr @blocklist drop
        
        # Allow established
        ct state established,related accept
        
        # Rate limit new connections
        udp dport 4433 ct state new \
            limit rate over 50/second burst 100 packets drop
        
        # Allow Oxidize
        udp dport 4433 accept
    }
}
```

---

## Monitoring & Alerting

### Prometheus Metrics

```yaml
# Alert rules for Grafana/Prometheus

groups:
  - name: oxidize_security
    rules:
      - alert: HighBlockRate
        expr: rate(oxidize_packets_blocked[5m]) > 1000
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High packet block rate detected"
          
      - alert: DDoSDetected
        expr: rate(oxidize_packets_rate_limited[1m]) > 10000
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Possible DDoS attack in progress"
          
      - alert: TooManyBlocks
        expr: oxidize_active_blocks > 100
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Unusual number of blocked IPs"
```

### Log Analysis

```bash
# Watch for attacks in real-time
journalctl -u oxidize -f | grep -E "(blocked|rate_limit|violation)"

# Count blocks per IP
journalctl -u oxidize --since "1 hour ago" | \
    grep "blocked" | \
    awk '{print $NF}' | \
    sort | uniq -c | sort -rn | head -20
```

---

## Client Authentication (Optional)

For additional security, require client certificates:

```toml
# Server config
[tls]
require_client_cert = true
client_ca_path = "/etc/oxidize/client-ca.pem"
```

```bash
# Generate client certificates
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out client.pem -days 365
```

---

## Incident Response

### During an Attack

```bash
# 1. Check current status
curl http://localhost:9090/metrics | grep oxidize_

# 2. View top offending IPs
oxidize-server --stats | grep "top_blocked"

# 3. Manually block subnet if needed
iptables -I INPUT -s 192.168.1.0/24 -j DROP

# 4. Enable stricter rate limits
oxidize-server --max-pps-per-ip 100 --reload-config
```

### Post-Attack Analysis

```bash
# Export blocked IPs
oxidize-server --dump-blocklist > blocked_ips.txt

# Analyze patterns
cat blocked_ips.txt | \
    cut -d'.' -f1-3 | \
    sort | uniq -c | sort -rn
```

---

## Security Recommendations Summary

| Priority | Recommendation | Impact |
|----------|----------------|--------|
| **Critical** | Enable rate limiting | Prevents resource exhaustion |
| **Critical** | Use valid TLS certificates | Prevents MITM |
| **High** | Configure firewall | Defense in depth |
| **High** | Enable stateless retry | Prevents spoofing |
| **Medium** | Set up monitoring | Early detection |
| **Medium** | OS hardening | Reduces attack surface |
| **Low** | Client certificates | Strong authentication |

---

## Comparison with Other Solutions

| Feature | Oxidize | WireGuard | OpenVPN |
|---------|---------|-----------|---------|
| Protocol | QUIC | Custom UDP | TLS/UDP |
| DDoS resistance | High | Medium | Low |
| Speed | Very Fast | Very Fast | Slow |
| Encryption | TLS 1.3 | ChaCha20 | Various |
| Multiplexing | ✅ | ❌ | ❌ |
| 0-RTT | ✅ | ❌ | ❌ |
| FEC | ✅ | ❌ | ❌ |
