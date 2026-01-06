# Smart Split-Tunneling

Oxidize uses **smart traffic classification** to route traffic optimally:
- **Gaming** → QUIC tunnel (optimized)
- **Streaming** → Direct (bypasses tunnel, uses your real IP)

## How It Works

```
┌────────────────────────────────────────────────────┐
│                  TUN INTERFACE                      │
│                       │                             │
│            ┌──────────┴──────────┐                 │
│            │  TRAFFIC CLASSIFIER │                 │
│            └──────────┬──────────┘                 │
│                       │                             │
│         ┌─────────────┼─────────────┐              │
│         ▼             ▼             ▼              │
│    ┌─────────┐   ┌─────────┐   ┌─────────┐        │
│    │ GAMING  │   │STREAMING│   │ GENERAL │        │
│    │ → QUIC  │   │→ BYPASS │   │ → QUIC  │        │
│    └────┬────┘   └────┬────┘   └────┬────┘        │
└─────────┼─────────────┼─────────────┼──────────────┘
          │             │             │
          ▼             ▼             ▼
      RELAY         YOUR IP        RELAY
    (optimized)    (clean!)     (optimized)
```

## Why This Matters

| Traffic | Route | IP Seen | Benefit |
|---------|-------|---------|---------|
| Gaming | QUIC Tunnel | Datacenter | Low latency, FEC, compression |
| Netflix | Bypass | Your residential IP | Never blocked |
| Browsing | QUIC Tunnel | Datacenter | Compressed, optimized |

## Bypass Domains (Default)

| Service | Domains |
|---------|---------|
| Netflix | netflix.com, nflxvideo.net |
| Disney+ | disneyplus.com, bamgrid.com |
| Hulu | hulu.com, hulustream.com |
| Prime Video | primevideo.com, amazonvideo.com |
| HBO Max | max.com, hbomax.com |
| Spotify | spotify.com, scdn.co |

## Gaming Ports (Tunneled)

| Platform | Ports |
|----------|-------|
| Steam/Source | 27015-27017 |
| Unreal Engine | 7777-7779 |
| Xbox Live | 3074 |
| PlayStation | 3478-3480 |
| Riot Games | 5060-5062 |

## Verify It's Working

```bash
# Run with verbose logging
sudo oxidize-client --server YOUR_SERVER:4433 --verbose 2>&1 | grep -E "BYPASS|TUNNEL"

# You should see:
# BYPASS: netflix.com -> 1.2.3.4:443 (streaming/bypass traffic)
# TUNNEL: game-server.com -> 5.6.7.8:27015 (optimized)
```

## Result

- **Netflix works** - sees your residential IP
- **Gaming optimized** - full QUIC tunnel benefits
- **No configuration** - automatic classification
