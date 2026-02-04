---
license: mit
tags:
  - networking
  - congestion-control
  - loss-prediction
  - rust
  - reinforcement-learning
  - transformer
  - ppo
  - int8-quantization
  - ucb1-bandit
library_name: candle
pipeline_tag: other
---

# 🦀 Oxidize ML Models

Machine learning models for [Oxidize](https://github.com/gagansuie/oxidize) — open source deep learning driven network acceleration built in pure Rust.

> Neural networks predict packet loss before it happens, optimize routing in real-time, and accelerate your network automatically.

## Highlights

- **10x faster inference** via INT8 quantization
- **<1µs cached latency** with speculative pre-computation
- **Pure Rust** — no Python runtime, trained with Candle
- **Self-improving** — automated training pipeline via CI/CD

## Models

### Tier 1 - Core Intelligence

| Model | Architecture | Latency | Purpose |
|-------|--------------|---------|---------|
| **transformer_loss** | MiniTransformer (d=64, 4 heads, INT8) | <10µs | Predict packet loss 50-100ms ahead |
| **ppo_congestion** | PPO Actor-Critic (continuous action) | <1µs | Optimize congestion window smoothly |

### Tier 2 - Advanced Optimization

| Model | Architecture | Latency | Purpose |
|-------|--------------|---------|---------|
| **compression_oracle** | MLP + entropy analysis | ~5µs | ML-based compression strategy selection |
| **path_selector** | UCB1 contextual bandit | <1µs | Learn optimal path per traffic type |

## Architecture

### Transformer Loss Predictor (INT8 Quantized)

```
Input: [batch, 20, 8]  →  MultiHeadAttention(d=64, h=4)  →  FFN  →  Linear(1)  →  Sigmoid  →  Loss probability
                                    ↓
                        INT8 Quantization (10x speedup)
                                    ↓
                    Speculative Cache (next 100 decisions pre-computed)
```

**Network Features (8):**
| Feature | Description | Normalization |
|---------|-------------|---------------|
| `rtt_us` | Round-trip time | / 1,000,000 |
| `rtt_var_us` | RTT variance (jitter) | / 500,000 |
| `bandwidth_bps` | Estimated bandwidth | / 10 Gbps |
| `loss_rate` | Recent packet loss | Raw (0-1) |
| `loss_trend` | Loss rate derivative | Raw |
| `inflight` | Packets in flight | / 10,000 |
| `cwnd` | Congestion window | / 1,000,000 |
| `buffer_occupancy` | Buffer fill level | Raw (0-1) |

### PPO Congestion Controller (Continuous Action)

```
Input: [batch, 8]  →  Actor(128)  →  ReLU  →  Actor(128)  →  ReLU  →  Gaussian(mean, log_std)  →  CWND multiplier
```

Smooth continuous control instead of discrete actions — no more CWND oscillation.

### UCB1 Path Selector

Multi-armed bandit with contextual bonuses per traffic type:

| Traffic Type | Optimization Target |
|--------------|---------------------|
| `Gaming` | Lowest latency, lowest jitter |
| `VoIP` | Low RTT, stable connection |
| `Streaming` | Highest bandwidth |
| `Bulk` | Maximum throughput |
| `Default` | Balanced |

```
UCB(path) = avg_reward + c × √(ln(total_pulls) / path_pulls) + context_bonus
```

### Smart Compression Oracle

Decides when/how to compress based on:
- Shannon entropy of byte distribution
- Byte frequency patterns
- Known file format magic bytes
- ASCII printable ratio
- Payload size

| Decision | When Used |
|----------|-----------|
| `Skip` | High entropy (encrypted/compressed) |
| `Light` | Medium entropy, time-sensitive |
| `Aggressive` | Low entropy, large payload |
| `RohcOnly` | Small packets with compressible headers |

## Performance

All ML operations designed for minimal hot-path latency:

| Operation | Typical Latency |
|-----------|-----------------|
| Loss prediction (cached) | **<1µs** |
| Loss prediction (uncached) | <50µs |
| CWND optimization | <10µs |
| Path selection | <5µs |
| FEC decision | <100ns |

Training runs asynchronously via `BackgroundTrainer` — never blocks the packet path.

## Usage

### With Oxidize (Rust)

```rust
use oxidize_common::ml_optimized::OptimizedMlEngine;

let engine = OptimizedMlEngine::new();

// Loss prediction (INT8 Transformer)
let loss_prob = engine.predict_loss(seq_num, &features);

// CWND optimization (PPO continuous)
let cwnd = engine.get_cwnd(rtt_us, &state);

// Path selection (UCB1 bandit)
let path = engine.select_path(TrafficContext::Gaming);
```

### Auto-Download Models

```rust
use oxidize_common::model_hub::ModelHub;

let hub = ModelHub::new(Default::default());
hub.download_models("/tmp/oxidize_models").await?;
engine.load_models("/tmp/oxidize_models")?;
```

### Environment Variables

```bash
export HF_TOKEN=hf_xxxxxxxxxx   # For private repos or uploads
export OXIDIZE_MODEL_DIR=/tmp/oxidize_models  # Local cache
```

## Training Pipeline (Fully Automated)

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐
│   Servers    │───▶│   HF Hub     │───▶│  CI/CD       │───▶│  HF Hub    │
│  (collect)   │    │  (storage)   │    │  (train)     │    │  (models)  │
└──────────────┘    └──────────────┘    └──────────────┘    └────────────┘
       │                    ▲                   │                    │
       └────────────────────┴───────────────────┴────────────────────┘
                            Continuous Loop
```

1. **Servers auto-collect** — `OptimizedMlEngine` collects training data by default
2. **Servers auto-upload** — Training data pushed to HF Hub hourly
3. **CI trains daily** — GitHub Actions aggregates and trains (3 AM UTC)
4. **Servers auto-download** — New models fetched from HF Hub on startup

### Data Quality Guards

Built-in validation prevents training on garbage data during DDoS attacks:
- Range validation (RTT, bandwidth, loss rate bounds)
- Consistency checks (RTT variance ≤ RTT)
- Timestamp validation (no future/stale data)
- Anomaly detection (duplicate/synthetic pattern rejection)

See [ML_DATA_QUALITY.md](https://github.com/gagansuie/oxidize/blob/main/docs/ML_DATA_QUALITY.md) for details.

## Model Files

| Model | File | Format |
|-------|------|--------|
| Loss Predictor | `transformer_loss.safetensors` | SafeTensors |
| Congestion Controller | `ppo_congestion.safetensors` | SafeTensors |

## Advanced Features (Implemented)

Additional capabilities in `oxidize_common::advanced_ml`:

- **Federated Learning** — Privacy-preserving distributed training with differential privacy
- **Multi-Agent RL** — Cooperative congestion control with inter-agent communication
- **A/B Testing Framework** — Statistical significance testing (Welch's t-test) for model deployment

## Heuristic Fallback

If models aren't loaded, all components fall back to fast heuristics:

| Component | Fallback |
|-----------|----------|
| Loss Predictor | Exponential weighted moving average |
| Congestion Controller | Standard congestion avoidance |
| Compression Oracle | Entropy threshold + magic byte detection |
| Path Selector | Round-robin with availability check |

## License

MIT OR Apache-2.0 — Same as Oxidize

## Citation

```bibtex
@software{oxidize2026,
  author = {gagansuie},
  title = {Oxidize: Open Source Deep Learning Driven Network Acceleration},
  url = {https://github.com/gagansuie/oxidize},
  year = {2026}
}
```

## Links

- **Code**: [github.com/gagansuie/oxidize](https://github.com/gagansuie/oxidize)
- **Website**: [oxd.sh](https://oxd.sh)
- **ML Docs**: [DEEP_LEARNING.md](https://github.com/gagansuie/oxidize/blob/main/docs/DEEP_LEARNING.md) · [ADVANCED_ML.md](https://github.com/gagansuie/oxidize/blob/main/docs/ADVANCED_ML.md)
