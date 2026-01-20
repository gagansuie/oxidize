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
library_name: candle
pipeline_tag: other
---

# 🦀 Oxidize ML Models

Machine learning models for [Oxidize](https://github.com/gagansuie/oxidize) - an enterprise-grade network backbone built in Rust.

## Models

### Tier 1 - Core Intelligence

| Model | Architecture | Purpose | Input | Output |
|-------|--------------|---------|-------|--------|
| **transformer_loss** | Transformer (d=64, 4 heads) | Predict packet loss 50-100ms ahead | 20×8 sequence | Loss probability |
| **ppo_congestion** | PPO Actor-Critic (128 hidden) | Optimize congestion window | 8-dim state | Continuous CWND |

### Tier 2 - Advanced Optimization

| Model | Architecture | Purpose | Input | Output |
|-------|--------------|---------|-------|--------|
| **compression_oracle** | MLP classifier | Decide optimal compression strategy | 8 features | 4 classes |
| **path_selector** | Contextual bandit | Select best path per traffic type | 29 features | 4 paths |

## Architecture

### Transformer Loss Predictor

```
Input: [batch, 20, 8]  →  MultiHeadAttention(d=64, h=4)  →  FFN  →  Linear(1)  →  Sigmoid  →  Loss probability
```

**Features (8):**
- RTT (normalized)
- RTT variance (jitter)
- Bandwidth estimate
- Current loss rate
- Packets in flight
- Buffer occupancy
- Inter-packet gap
- Time since last loss

### PPO Congestion Controller

```
Input: [batch, 8]  →  Actor(128)  →  ReLU  →  Actor(128)  →  ReLU  →  (mean, log_std)  →  CWND multiplier
```

**Actions (6):**
- `DecreaseLarge` (-25% CWND)
- `DecreaseSmall` (-10% CWND)
- `Maintain` (0%)
- `IncreaseSmall` (+5% CWND)
- `IncreaseAdditive` (+1 MSS)
- `IncreaseLarge` (+10% CWND)

## Usage

### With Oxidize (Rust)

```rust
use oxidize_common::model_hub::{ModelHub, HubConfig};

let hub = ModelHub::default_config();
let paths = hub.download_models()?;

// Models auto-loaded into ML engine
```

### Environment Variables

```bash
# Optional: For private repos or uploads
export HF_TOKEN=hf_xxxxxxxxxx
```

## Training

Models are trained on real network telemetry from Oxidize deployments:

1. **Data Collection**: Servers collect `LossSample` and `DrlExperience` during operation
2. **Aggregation**: Training data uploaded to this repo's `training_data/` folder
3. **Training**: Candle-based training in pure Rust
4. **Deployment**: Updated models pushed here, servers auto-sync

## Contributing Training Data

Oxidize servers can opt-in to contribute anonymized training data:

```rust
let config = HubConfig {
    upload_training_data: true,
    ..Default::default()
};
```

## License

MIT - Same as Oxidize

## Citation

```bibtex
@software{oxidize2026,
  author = {gagansuie},
  title = {Oxidize: Enterprise-grade network backbone},
  url = {https://github.com/gagansuie/oxidize},
  year = {2026}
}
```
