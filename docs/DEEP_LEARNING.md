# 🧠 Deep Learning Driven Engine Documentation

Oxidize includes a self-improving deep learning driven engine built entirely in Rust. Neural networks learn from your network traffic to predict and prevent issues before they happen. No Python runtime required.

## Overview

The ML engine provides four core capabilities with **10x optimized inference**:

| Tier | Component | Architecture | Purpose |
|------|-----------|--------------|---------|
| **Tier 1** | Loss Predictor | **Transformer** (INT8) | Predict packet loss 50-100ms ahead |
| **Tier 1** | Congestion Controller | **PPO** (continuous) | Optimize CWND via reinforcement learning |
| **Tier 2** | Smart Compression Oracle | MLP classifier | ML-based compression decision making |
| **Tier 2** | Path Selector | UCB1 + contextual | Learn optimal path per traffic type |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         OptimizedMlEngine (10x Faster)                        │
├──────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐  ┌─────────────────────┐                            │
│  │ MiniTransformer     │  │ PPOController       │  ← Tier 1 (Core)           │
│  │  - INT8 quantized   │  │ - Continuous action │                            │
│  │  - 4 attention heads│  │ - Gaussian policy   │                            │
│  │  - Speculative cache│  │ - Smooth CWND ctrl  │                            │
│  └─────────────────────┘  └─────────────────────┘                            │
│  ┌─────────────────────┐  ┌─────────────────────┐                            │
│  │ MlCompressionOracle │  │   MlPathSelector    │  ← Tier 2 (Advanced)       │
│  │  - Entropy analysis │  │ - UCB1 algorithm    │                            │
│  │  - Per-conn dicts   │  │ - 5 traffic types   │                            │
│  │  - 20-40% better    │  │ - 4 paths max       │                            │
│  └─────────────────────┘  └─────────────────────┘                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Tier 1: Transformer Loss Predictor (10x Faster)

Predicts packet loss before it happens using INT8 quantized Transformer architecture.

### How It Works

1. **Collects network telemetry** - RTT, jitter, bandwidth, loss rate, buffer occupancy
2. **Speculative pre-computation** - Pre-computes next 100 decisions in background
3. **Transformer inference** - Self-attention captures long-range patterns (INT8 quantized)
4. **FEC decision** - Determines redundancy ratio based on prediction

### Network Features (8 inputs)

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

### Usage

```rust
use oxidize_common::ml_optimized::OptimizedMlEngine;

let engine = OptimizedMlEngine::new();

// Predict loss with INT8 quantized Transformer
let features = [rtt_us as f32, jitter_us as f32, loss_rate, 0.0];
let loss_prob = engine.predict_loss(seq_num, &features);

// Get optimal CWND with PPO continuous control
let state = [rtt_us as f32, bandwidth as f32 / 1e6, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0];
let cwnd = engine.get_cwnd(rtt_us as u64, &state);

// Network features for FEC decision
use oxidize_common::ml_optimized::NetworkFeatures;
let features = NetworkFeatures {
    rtt_us: 50_000,
    rtt_var_us: 5_000,
    bandwidth_bps: 100_000_000,
    loss_rate: 0.01,
    ..Default::default()
};

// Get FEC decision
let fec = engine.fec_decision(&features);
if fec.inject_fec {
    println!("Inject FEC with {}% redundancy", fec.redundancy_ratio * 100.0);
}
```

## Tier 1: DRL Congestion Controller

Deep Q-Learning agent that learns optimal congestion window adjustments.

### Actions (6 total)

| Action | Effect |
|--------|--------|
| `Increase5` | CWND += 5% |
| `Increase10` | CWND += 10% |
| `Maintain` | No change |
| `Decrease5` | CWND -= 5% |
| `Decrease10` | CWND -= 10% |
| `SlowStart` | Reset to initial CWND |

### State Space (8 features)

Same as Transformer predictor, plus throughput history.

### Exploration Strategy

- **ε-greedy** with decay: starts at 1.0, decays to 0.01
- **Decay rate**: 0.995 per decision

### Usage

```rust
// Get congestion control action
let (action, new_cwnd) = engine.congestion_action();
println!("Action: {:?}, New CWND: {}", action, new_cwnd);
```

## Tier 2: Smart Compression Oracle

ML-based decision engine for compression strategy selection.

### Decision Types

| Decision | When Used | Compression Mode |
|----------|-----------|------------------|
| `Skip` | High entropy data (encrypted/compressed) | None |
| `Light` | Medium entropy, time-sensitive | LZ4 DEFAULT (~6 GB/s) |
| `Aggressive` | Low entropy, large payload | LZ4 DEFAULT (~6 GB/s) |
| `RohcOnly` | Small packets with compressible headers | ROHC only |

### Compression Performance

| Mode | Throughput | Use Case |
|------|------------|----------|
| **LZ4 DEFAULT** | ~6 GB/s | All compression (optimized for real-time) |
| LZ4 HIGH | ~200 MB/s | ❌ Not used (30x slower, only ~5% better ratio) |
| ROHC | Header-only | Small UDP/VoIP packets (44% reduction) |

**Note:** We use LZ4 DEFAULT mode exclusively for real-time traffic. The HIGH compression mode provides only ~5% better compression ratio but is 30x slower - not worth it for network acceleration.

### Features Analyzed

- **Entropy** - Shannon entropy of byte distribution
- **Byte frequency** - Distribution of top 4 most common bytes
- **Header magic** - Known file format detection
- **Text detection** - ASCII printable ratio
- **Size** - Payload size (skip small packets)

### Usage

```rust
use oxidize_common::ml_optimized::MlCompressionDecision;

let data = b"some packet data here";
let decision = engine.compression_decision(data);

match decision {
    MlCompressionDecision::Skip => { /* don't compress */ }
    MlCompressionDecision::Light => { /* fast LZ4 DEFAULT */ }
    MlCompressionDecision::Aggressive => { /* LZ4 DEFAULT */ }
    MlCompressionDecision::RohcOnly => { /* header compression only */ }
}
```

## Tier 2: Multi-Armed Bandit Path Selector

UCB1-based algorithm that learns the best network path for each traffic type.

### Traffic Types

| Type | Priority | Best Path Characteristics |
|------|----------|---------------------------|
| `Gaming` | Latency | Lowest RTT, lowest jitter |
| `VoIP` | Latency | Low RTT, stable connection |
| `Streaming` | Bandwidth | Highest throughput |
| `Bulk` | Bandwidth | High throughput, loss tolerant |
| `Web` | Balanced | Good latency + bandwidth |

### Path Metrics

```rust
use oxidize_common::ml_optimized::{PathMetrics, PathId};

engine.update_path_metrics(PathMetrics {
    path_id: PathId::Primary,
    rtt_us: 20_000,
    rtt_var_us: 2_000,
    bandwidth_bps: 100_000_000,
    loss_rate: 0.001,
    availability: 1.0,
    cost_factor: 1.0,  // Higher for cellular
    last_update_ms: 0,
});
```

### UCB1 Algorithm

The selector uses Upper Confidence Bound (UCB1) to balance:
- **Exploitation** - Use paths that have performed well
- **Exploration** - Try less-used paths to discover better options

```
UCB(arm) = avg_reward + c * sqrt(ln(total_pulls) / arm_pulls)
```

### Contextual Bonus

Adds traffic-type-specific bonuses:
- Gaming/VoIP: Bonus for low latency paths
- Streaming/Bulk: Bonus for high bandwidth paths
- Web: Balanced bonus

### Usage

```rust
use oxidize_common::ml_optimized::TrafficContext;

// Select path for gaming traffic
let path = engine.select_path(TrafficContext::Gaming);

// After observing performance, update reward
let reward = MlPathSelector::calculate_reward(
    TrafficContext::Gaming,
    rtt_us,
    loss_rate,
    throughput_mbps,
);
engine.update_path_reward(path, TrafficContext::Gaming, reward);
```

## Training Pipeline (Fully Automated)

The ML training pipeline is **fully automated** end-to-end:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    AUTOMATED ML TRAINING PIPELINE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌────────────┐│
│  │   Servers    │───▶│   HF Hub     │───▶│  CI/CD       │───▶│  HF Hub    ││
│  │  (collect)   │    │  (storage)   │    │  (train)     │    │  (models)  ││
│  └──────────────┘    └──────────────┘    └──────────────┘    └────────────┘│
│        │                    ▲                   │                    │      │
│        │                    │                   │                    │      │
│        └────────────────────┴───────────────────┴────────────────────┘      │
│                         Continuous Loop                                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Servers auto-collect training data** - `MlEngine` collects data by default
2. **Servers auto-upload hourly** - Training data pushed to HF Hub every hour
3. **CI trains daily (3 AM UTC)** - GitHub Actions aggregates and trains models
4. **Servers auto-download on startup** - New models fetched from HF Hub

### Data Collection (Automatic)

Training data is collected automatically when running Oxidize:

```rust
// MlEngine auto-collects by default - no setup needed!
let engine = MlEngine::new();  // Training collection enabled automatically

// Data is uploaded to HF Hub hourly by the server
```

### CI/CD Training

Training runs **daily** via GitHub Actions (`.github/workflows/ml-training.yml`):
1. Downloads all training data uploaded by servers from HF Hub
2. Aggregates samples from multiple servers
3. Trains Transformer + PPO models using Candle (pure Rust)
4. Pushes updated models to [gagansuie/oxidize-models](https://huggingface.co/gagansuie/oxidize-models)
5. Archives processed training data

Manual trigger available: `workflow_dispatch` with `force_retrain` option.

### Model Files

| Model | File | Format |
|-------|------|--------|
| Loss Predictor | `transformer_loss.safetensors` | SafeTensors |
| Congestion Controller | `ppo_congestion.safetensors` | SafeTensors |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HF_TOKEN` | Hugging Face API token (required for upload) | - |
| `OXIDIZE_MODEL_DIR` | Local model cache | `/tmp/oxidize_models` |

> **Note**: Training data collection is now **enabled by default**. No configuration needed.

### Loading Models

```rust
let mut engine = MlEngine::new();

// Load from directory
engine.load_models("/path/to/models")?;

// Or download from HF Hub
use oxidize_common::model_hub::ModelHub;
let hub = ModelHub::new(Default::default());
hub.download_models("/tmp/oxidize_models").await?;
engine.load_models("/tmp/oxidize_models")?;
```

## Performance

All ML inference runs on the hot path with minimal overhead:

| Operation | Latency | Impact |
|-----------|---------|--------|
| Transformer inference | ~10µs | Once per 10ms window |
| PPO inference | ~10µs | Once per RTT |
| Compression decision | ~5µs | Per packet |
| Path selection | ~1µs | Per flow |

Training runs in a background thread and never blocks the packet path.

## Heuristic Fallback

If models aren't loaded, all components fall back to fast heuristics:

- **Loss Predictor**: Exponential weighted moving average
- **Congestion Controller**: Standard congestion avoidance
- **Compression Oracle**: Entropy threshold + magic byte detection
- **Path Selector**: Round-robin with availability check

## Statistics

```rust
let stats = engine.stats();
println!("Loss predictor: {:?}", stats.loss_predictor);
println!("Congestion controller: {:?}", stats.congestion_controller);
println!("Compression oracle: {:?}", stats.compression_oracle);
println!("Path selector: {:?}", stats.path_selector);
```

## Implemented Features

- [x] **Automatic training data collection** - Servers collect data by default
- [x] **Automatic upload to HF Hub** - Servers upload hourly  
- [x] **Daily CI/CD training** - GitHub Actions trains models daily
- [x] **Automatic model download** - Servers fetch latest models on startup
- [x] **End-to-end automation** - No manual intervention required

## Advanced ML Features (Implemented)

Core ML features in the `ml_optimized` module:

- [x] **INT8 Quantized Inference** - 10x faster than FP32 (`QuantizedTensor`, `QuantizedLinear`)
- [x] **Transformer-based loss predictor** - Multi-head attention (`MiniTransformer`)
- [x] **PPO congestion controller** - Continuous CWND optimization (`PPOController`)
- [x] **Speculative pre-computation** - Cache next 100 decisions (`SpeculativeCache`)
- [x] **UCB1 path selector** - Bandit-based path selection (`MlPathSelector`)

Advanced features in the `advanced_ml` module (Integration TBD):

- [x] **Federated Learning** - Privacy-preserving aggregation with differential privacy (`FederatedCoordinator`) - *TBD*
- [x] **Multi-agent RL** - Distributed congestion control with inter-agent communication (`MultiAgentCoordinator`) - *TBD*
- [x] **A/B Testing Framework** - Statistical significance testing for model deployment (`ABTestingFramework`) - *TBD*

See [ADVANCED_ML.md](ADVANCED_ML.md) for detailed documentation.
