# Zero-Downtime Deployment Guide

This guide explains how to update Oxidize servers **without any user impact**.

## How It Works

### Server Side
```
┌─────────────────────────────────────────────────────────────────┐
│                    ZERO-DOWNTIME UPDATE FLOW                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. New server starts ──► Binds to same port (SO_REUSEPORT)     │
│                              │                                   │
│  2. Old server receives ◄────┘                                   │
│     SIGTERM signal                                               │
│           │                                                      │
│           ▼                                                      │
│  3. Old server stops accepting new connections                   │
│     (new connections go to new server)                           │
│           │                                                      │
│           ▼                                                      │
│  4. Old server drains existing connections (30s timeout)         │
│           │                                                      │
│           ▼                                                      │
│  5. Old server exits cleanly                                     │
│                                                                  │
│  Result: Users experience 0ms downtime                           │
└─────────────────────────────────────────────────────────────────┘
```

### Client Side
```
┌─────────────────────────────────────────────────────────────────┐
│                    CLIENT SEAMLESS RECONNECT                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Connection drops (server restart)                            │
│           │                                                      │
│           ▼                                                      │
│  2. Instant retry (50ms) ──► Connects to new server             │
│           │                                                      │
│           ▼                                                      │
│  3. Buffered packets replayed automatically                      │
│           │                                                      │
│           ▼                                                      │
│  4. User continues without noticing                              │
│                                                                  │
│  Worst case: ~50-100ms of buffered packets                       │
└─────────────────────────────────────────────────────────────────┘
```

## Deployment Methods

### Method 1: Automated Script (Recommended)
```bash
# Build and deploy with health checks and auto-rollback
sudo ./scripts/zero-downtime-deploy.sh

# Rollback if needed
sudo ./scripts/zero-downtime-deploy.sh --rollback
```

### Method 2: Systemd (Simple)
```bash
# Standard restart with graceful shutdown
sudo systemctl restart oxidize-daemon

# Or reload (if config-only changes)
sudo systemctl reload oxidize-daemon
```

### Method 3: Manual Rolling Restart
```bash
# 1. Build new binary
cargo build --release --package relay-server

# 2. Copy to install location (atomic)
sudo cp target/release/oxidize-server /usr/local/bin/oxidize-server.new
sudo mv /usr/local/bin/oxidize-server.new /usr/local/bin/oxidize-server

# 3. Restart service (graceful)
sudo systemctl restart oxidize-daemon
```

## Configuration

### Client Config (Reconnection Tuning)
```toml
# config.toml
[client]
# Instant first retry for rolling restarts
reconnect_delay_ms = 50

# Max delay during sustained outages  
max_reconnect_delay_ms = 5000

# 0 = infinite retries (recommended for always-on acceleration)
max_reconnect_attempts = 0

# Buffer packets during reconnection
reconnect_buffer_size = 1000
```

### Server Config (Drain Timeout)
The server waits up to 30 seconds for connections to drain gracefully.
This is configured in `graceful.rs`:
```rust
ShutdownCoordinator::new(Duration::from_secs(30))
```

## Verification

### Health Check Endpoint
```bash
# Check if server is healthy and ready
curl http://localhost:9090/health
# Returns: {"status":"healthy","ready":true}
```

### Monitor During Deploy
```bash
# Watch active connections during deployment
watch -n1 'curl -s http://localhost:9090/metrics | grep connections_active'
```

### Test Zero-Downtime
```bash
# In terminal 1: Run continuous ping through tunnel
ping -i 0.1 8.8.8.8

# In terminal 2: Deploy update
sudo ./scripts/zero-downtime-deploy.sh

# Observe: No dropped pings!
```

## Architecture Details

### SO_REUSEPORT
- Multiple processes can bind to the same UDP port
- Kernel load-balances incoming packets between them
- Enables seamless handoff between old and new server

### Graceful Shutdown
- SIGTERM triggers graceful shutdown
- Server stops accepting new connections
- Existing connections allowed to complete (30s max)
- Connection count tracked for monitoring

### Client Packet Buffering
- Up to 1000 packets buffered during reconnection
- Packets replayed in order after reconnect
- TCP connections see brief stall but don't drop
- UDP/real-time traffic minimally impacted

## Troubleshooting

### Connections Not Draining
```bash
# Check active connections
curl -s http://localhost:9090/metrics | grep connections

# Force kill after timeout (not recommended)
sudo systemctl kill -s SIGKILL oxidize-daemon
```

### New Server Won't Start
```bash
# Check if port is in use
sudo ss -tulpn | grep 51820

# Check service logs
journalctl -u oxidize-daemon -f
```

### Client Not Reconnecting
```bash
# Check client logs
journalctl -u oxidize-client -f

# Verify server is healthy
curl http://SERVER_IP:9090/health
```

## Best Practices

1. **Always use the deployment script** - It includes health checks and rollback
2. **Monitor during deploys** - Watch the metrics endpoint
3. **Test in staging first** - Verify zero-downtime works in your environment
4. **Keep backups** - The script auto-keeps last 3 binary versions
5. **Use socket activation** - For even faster handoff on Linux
