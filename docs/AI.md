# 🤖 AI/ML Engine Documentation

Oxidize includes a self-improving AI/ML engine built entirely in Rust. No Python runtime required.

## Overview

The ML engine provides four core capabilities:

| Tier | Component | Purpose |
|------|-----------|---------|
| **Tier 1** | LSTM Loss Predictor | Predict packet loss 50-100ms ahead |
| **Tier 1** | DRL Congestion Controller | Optimize CWND via reinforcement learning |
| **Tier 2** | Smart Compression Oracle | ML-based compression decision making |
| **Tier 2** | Multi-Armed Bandit Path Selector | Learn optimal path per traffic type |

## Architecture

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              MlEngine                                         │
├──────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────────────┐  ┌─────────────────────┐                            │
│  │  LstmLossPredictor  │  │ DrlCongestionCtrl   │  ← Tier 1 (Core)           │
│  │  - 64 hidden units  │  │ - DQN (128 hidden)  │                            │
│  │  - 20 seq length    │  │ - 6 actions         │                            │
│  │  - 8 features       │  │ - ε-greedy explore  │                            │
│  └─────────────────────┘  └─────────────────────┘                            │
│  ┌─────────────────────┐  ┌─────────────────────┐                            │
│  │ MlCompressionOracle │  │   MlPathSelector    │  ← Tier 2 (Advanced)       │
│  │  - Entropy analysis │  │ - UCB1 algorithm    │                            │
│  │  - 4 decision types │  │ - 5 traffic types   │                            │
│  │  - Byte frequency   │  │ - 4 paths max       │                            │
│  └─────────────────────┘  └─────────────────────┘                            │
└──────────────────────────────────────────────────────────────────────────────┘
```

## Tier 1: LSTM Loss Predictor

Predicts packet loss before it happens, enabling proactive FEC injection.

### How It Works

1. **Collects network telemetry** - RTT, jitter, bandwidth, loss rate, buffer occupancy
2. **Maintains sliding window** - Last 20 observations (configurable)
3. **LSTM inference** - Predicts loss probability for next 50-100ms
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
use oxidize_common::ml_models::{MlEngine, NetworkFeatures};

let mut engine = MlEngine::new();
engine.enable_training_collection();

// Record observations
let features = NetworkFeatures {
    rtt_us: 50_000,
    rtt_var_us: 5_000,
    bandwidth_bps: 100_000_000,
    loss_rate: 0.01,
    loss_trend: 0.0,
    inflight: 100,
    cwnd: 65535,
    time_since_loss_ms: 1000,
    buffer_occupancy: 0.3,
    recent_retx: 0,
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

Same as LSTM predictor, plus throughput history.

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

| Decision | When Used |
|----------|-----------|
| `Skip` | High entropy data (encrypted/compressed) |
| `Light` | Medium entropy, time-sensitive |
| `Aggressive` | Low entropy, large payload |
| `RohcOnly` | Small packets with compressible headers |

### Features Analyzed

- **Entropy** - Shannon entropy of byte distribution
- **Byte frequency** - Distribution of top 4 most common bytes
- **Header magic** - Known file format detection
- **Text detection** - ASCII printable ratio
- **Size** - Payload size (skip small packets)

### Usage

```rust
use oxidize_common::ml_models::MlCompressionDecision;

let data = b"some packet data here";
let decision = engine.compression_decision(data);

match decision {
    MlCompressionDecision::Skip => { /* don't compress */ }
    MlCompressionDecision::Light => { /* fast LZ4 */ }
    MlCompressionDecision::Aggressive => { /* high ratio LZ4 */ }
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
use oxidize_common::ml_models::{PathMetrics, PathId};

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
use oxidize_common::ml_models::{TrafficContext, MlPathSelector};

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

## Training

### Local Training (Candle)

Models can be trained entirely in Rust using Candle:

```rust
use oxidize_common::ml_training::{BackgroundTrainer, TrainingConfig};

let config = TrainingConfig::default();
let trainer = BackgroundTrainer::new(config);
trainer.start();
```

### Distributed Training (Hugging Face Hub)

Production servers collect telemetry and export training data:

```rust
// Export all training data
engine.export_training_data("/tmp/oxidize_training")?;
```

Training runs weekly via GitHub Actions:
1. Download aggregated training data from HF Hub
2. Train models using Candle
3. Push updated models to [gagansuie/oxidize-models](https://huggingface.co/gagansuie/oxidize-models)
4. Servers auto-sync new models

### Model Files

| Model | File | Format |
|-------|------|--------|
| Loss Predictor | `loss_predictor.onnx` | ONNX |
| Congestion Controller | `congestion_controller.onnx` | ONNX |
| Compression Oracle | `compression_oracle.onnx` | ONNX |
| Path Selector | `path_selector.onnx` | ONNX |

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `HF_TOKEN` | Hugging Face API token | - |
| `OXIDIZE_MODEL_DIR` | Local model cache | `/tmp/oxidize_models` |
| `OXIDIZE_COLLECT_TRAINING` | Enable training data collection | `false` |

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
| LSTM inference | ~50µs | Once per 10ms window |
| DQN inference | ~30µs | Once per RTT |
| Compression decision | ~5µs | Per packet |
| Path selection | ~1µs | Per flow |

Training runs in a background thread and never blocks the packet path.

## Heuristic Fallback

If models aren't loaded, all components fall back to fast heuristics:

- **Loss Predictor**: Exponential weighted moving average
- **Congestion Controller**: BBRv3-inspired algorithm
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

## Future Improvements

- [ ] Online learning (update models from live traffic)
- [ ] Federated learning (privacy-preserving aggregation)
- [ ] Transformer-based loss predictor
- [ ] Multi-agent RL for congestion control
- [ ] Neural network path selector (replacing UCB1)
