# 🚀 Advanced ML Features Documentation

This document covers the ML features implemented in Oxidize for network optimization.

## 10x Optimized ML Engine (`ml_optimized` module)

The optimized ML engine provides **10x faster inference** with minimal accuracy loss:

| Feature | Old | New | Improvement |
|---------|-----|-----|-------------|
| **Inference** | FP32 | INT8 Quantized | 10x faster |
| **Loss Predictor** | Heuristic | Transformer | Better accuracy |
| **Congestion Control** | Discrete | PPO (continuous) | Smoother CWND |
| **Caching** | None | Speculative pre-computation | Near-zero latency |

### INT8 Quantization

```rust
use oxidize_common::ml_optimized::OptimizedMlEngine;

let engine = OptimizedMlEngine::new();

// Predict loss (INT8 quantized Transformer)
let loss_prob = engine.predict_loss(seq_num, &features);

// Get optimal CWND (PPO continuous control)
let cwnd = engine.get_cwnd(rtt_us, &state);
```

### Speculative Pre-computation

The engine pre-computes the next 100 decisions in the background:
- Cache hit: **<1µs** latency
- Cache miss: **<50µs** latency (still 10x faster than old)

---

## ML Path Selector

UCB1 bandit-based path selection for optimal routing per traffic type:

```rust
use oxidize_common::ml_optimized::{OptimizedMlEngine, TrafficContext, PathId};

let mut engine = OptimizedMlEngine::new();

// Select best path for traffic type
let path = engine.select_path(TrafficContext::Gaming);

// Update with observed reward
engine.update_path_reward(PathId::Primary, TrafficContext::Gaming, 0.95);
```

### Traffic Contexts

| Context | Optimization Target |
|---------|---------------------|
| `Gaming` | Lowest latency |
| `Streaming` | Highest bandwidth |
| `VoIP` | Lowest jitter |
| `Bulk` | Maximum throughput |
| `Default` | Balanced |

---

## FEC Decision Engine

ML-based Forward Error Correction decisions:

```rust
use oxidize_common::ml_optimized::{OptimizedMlEngine, NetworkFeatures};

let engine = OptimizedMlEngine::new();

let features = NetworkFeatures {
    rtt_us: 50_000,
    rtt_var_us: 5_000,
    bandwidth_bps: 100_000_000,
    loss_rate: 0.01,
    ..Default::default()
};

let fec = engine.fec_decision(&features);
if fec.inject_fec {
    println!("Inject FEC with {}% redundancy", fec.redundancy_ratio * 100.0);
}
```

---

## Performance Impact

All ML operations are designed for minimal hot-path latency:

| Operation | Typical Latency |
|-----------|-----------------|
| Loss prediction (cached) | <1µs |
| Loss prediction (uncached) | <50µs |
| CWND optimization | <10µs |
| Path selection | <5µs |
| FEC decision | <100ns |

Training operations run asynchronously via `BackgroundTrainer` and never block the packet path.

---

---

## Advanced Features (Implemented, Integration TBD)

The following features are fully implemented and tested but not yet wired into the server runtime.
They are available as APIs in `oxidize_common::advanced_ml` for future integration.

---

## Federated Learning (`advanced_ml` module)

> **Status: Integration TBD** - Requires multi-server deployment + central aggregation service

Privacy-preserving model training across distributed servers with differential privacy.

```rust
use oxidize_common::advanced_ml::{FederatedConfig, FederatedCoordinator, FederatedClientUpdate, anonymize_client_id};

let config = FederatedConfig {
    enable_dp: true,
    dp_epsilon: 1.0,
    dp_noise_multiplier: 1.1,
    dp_clip_norm: 1.0,
    min_clients: 3,
    round_duration_secs: 3600,
    secure_aggregation: true,
};

let coordinator = FederatedCoordinator::new(config, initial_weights);

// Submit client updates
coordinator.submit_update(FederatedClientUpdate {
    client_hash: anonymize_client_id("server-123"),
    round: coordinator.current_round(),
    weight_deltas: vec![0.1; 10],
    num_samples: 1000,
    local_loss: 0.05,
    timestamp_ms: now(),
})?;

// Aggregate when ready
if coordinator.should_aggregate() {
    if let Some(new_weights) = coordinator.aggregate() {
        broadcast_model(&new_weights);
    }
}
```

### Differential Privacy

- **Gradient Clipping**: Bounds sensitivity of each update
- **Gaussian Noise**: Calibrated noise added to aggregated gradients
- **Privacy Accounting**: Tracks cumulative epsilon budget

---

## Multi-Agent RL for Congestion Control

> **Status: Integration TBD** - For research/experimentation with multi-flow RL

Distributed reinforcement learning with inter-agent communication for fairness.

```rust
use oxidize_common::advanced_ml::{MultiAgentCoordinator, MultiAgentConfig, CongestionAction, calculate_cooperative_reward};

let coordinator = MultiAgentCoordinator::new(MultiAgentConfig::default());

// Register agents (one per flow)
coordinator.register_agent("flow_1".to_string());
coordinator.register_agent("flow_2".to_string());

// Update state and select action
coordinator.update_state("flow_1", vec![rtt, loss, bw, ...]);
let action = coordinator.select_action("flow_1");
let new_cwnd = action.apply(current_cwnd);

// Record cooperative reward
let reward = calculate_cooperative_reward(
    agent_throughput,
    agent_latency_ms,
    total_throughput,
    fairness_index,
);
coordinator.record_reward("flow_1", reward);
```

### Actions

| Action | Effect |
|--------|--------|
| `Increase5` | CWND += 5% |
| `Increase10` | CWND += 10% |
| `Maintain` | No change |
| `Decrease5` | CWND -= 5% |
| `Decrease10` | CWND -= 10% |
| `SlowStart` | Reset to 10 MSS |

---

## A/B Testing Framework

> **Status: Integration TBD** - For A/B testing model variants in production

Statistical experimentation for model deployment with Welch's t-test.

```rust
use oxidize_common::advanced_ml::{ABTestingFramework, ABTestConfig, ModelVariant, ABSample};

let framework = ABTestingFramework::new();

let exp_id = framework.create_experiment(
    "transformer_vs_heuristic".to_string(),
    ModelVariant { name: "heuristic".into(), model_path: "/m/h.safetensors".into(), is_treatment: false },
    ModelVariant { name: "transformer".into(), model_path: "/m/t.safetensors".into(), is_treatment: true },
    ABTestConfig { min_samples: 100, confidence_level: 0.95, treatment_fraction: 0.5, ..Default::default() },
);

// Assign users deterministically
let is_treatment = framework.get_assignment(&exp_id, &user_id)?;

// Record samples
framework.record_sample(&exp_id, ABSample {
    is_treatment,
    metric_value: measured_throughput,
    timestamp_ms: now(),
});

// Get results
if let Some(result) = framework.get_result(&exp_id) {
    println!("Winner: {} (lift: {:.1}%, p={:.4})", result.winner, result.lift_percent, result.p_value);
}
```

### Features

- **Welch's t-test**: Handles unequal variances
- **Early stopping**: Auto-conclude on significance
- **Deterministic assignment**: Consistent user bucketing
