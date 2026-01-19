# 🚀 Advanced ML Features Documentation

This document covers the ML features implemented in Oxidize for network optimization.

## 10x Optimized ML Engine (`ml_optimized` module)

The new optimized ML engine provides **10x faster inference** with minimal accuracy loss:

| Feature | Old | New | Improvement |
|---------|-----|-----|-------------|
| **Inference** | FP32 | INT8 Quantized | 10x faster |
| **Loss Predictor** | LSTM | Transformer | Better accuracy |
| **Congestion Control** | DQN (discrete) | PPO (continuous) | Smoother CWND |
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

## Advanced Features (Scale-Ready)

| Feature | Purpose | Latency Impact | Memory | When Needed |
|---------|---------|----------------|--------|-------------|
| **Federated Learning** | Privacy-preserving training | Async | ~1MB/client | Multi-server |
| **Multi-agent RL** | Distributed congestion control | ~50µs/action | ~2MB/agent | Multi-flow fairness |
| **A/B Testing** | Model deployment experiments | ~1µs | ~100KB/exp | Always |

## 1. Federated Learning

Privacy-preserving model training across distributed servers.

### Architecture

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│   Server 1   │    │   Server 2   │    │   Server N   │
│  (Training)  │    │  (Training)  │    │  (Training)  │
└──────┬───────┘    └──────┬───────┘    └──────┬───────┘
       │                   │                   │
       │  Clipped +        │  Clipped +        │  Clipped +
       │  Noised Δw        │  Noised Δw        │  Noised Δw
       │                   │                   │
       └─────────────┬─────┴─────────┬─────────┘
                     │               │
                     ▼               ▼
              ┌──────────────────────────┐
              │   FederatedCoordinator   │
              │  ┌────────────────────┐  │
              │  │ FedAvg Aggregation │  │
              │  └────────────────────┘  │
              │  ┌────────────────────┐  │
              │  │ Privacy Accountant │  │
              │  └────────────────────┘  │
              └──────────────────────────┘
```

### Differential Privacy

The coordinator applies differential privacy to protect individual client data:

1. **Gradient Clipping**: Bounds sensitivity of each update
2. **Gaussian Noise**: Adds calibrated noise to aggregated gradients
3. **Privacy Accounting**: Tracks cumulative privacy budget spent

### Configuration

```rust
use oxidize_common::advanced_ml::{FederatedConfig, FederatedCoordinator};

let config = FederatedConfig {
    enable_dp: true,
    dp_epsilon: 1.0,           // Privacy budget
    dp_noise_multiplier: 1.1,  // Noise scale
    dp_clip_norm: 1.0,         // Gradient clipping
    min_clients: 3,            // Minimum for aggregation
    round_duration_secs: 3600, // 1 hour rounds
    secure_aggregation: true,
};

let coordinator = FederatedCoordinator::new(config, initial_weights);
```

### Client Updates

```rust
use oxidize_common::advanced_ml::{FederatedClientUpdate, anonymize_client_id};

// On each client/server
let update = FederatedClientUpdate {
    client_hash: anonymize_client_id("server-123"),
    round: coordinator.current_round(),
    weight_deltas: compute_local_gradients(),
    num_samples: 1000,
    local_loss: 0.05,
    timestamp_ms: now(),
};

coordinator.submit_update(update)?;
```

### Aggregation

```rust
// On coordinator (runs periodically)
if coordinator.should_aggregate() {
    if let Some(new_weights) = coordinator.aggregate() {
        // Distribute new global model to all clients
        broadcast_model(&new_weights);
    }
}
```

## 2. Multi-agent RL for Congestion Control

Distributed reinforcement learning with inter-agent communication.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   MultiAgentCoordinator                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌─────────┐      ┌─────────┐      ┌─────────┐             │
│   │ Agent 1 │◄────▶│ Agent 2 │◄────▶│ Agent N │             │
│   │  (DQN)  │ msg  │  (DQN)  │ msg  │  (DQN)  │             │
│   └────┬────┘      └────┬────┘      └────┬────┘             │
│        │                │                │                   │
│        └────────────────┼────────────────┘                   │
│                         │                                    │
│                         ▼                                    │
│              ┌──────────────────────┐                        │
│              │ Cooperative Reward   │                        │
│              │ 0.7*individual +     │                        │
│              │ 0.3*global*fairness  │                        │
│              └──────────────────────┘                        │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Actions (Same as single-agent DQN)

| Action | Effect |
|--------|--------|
| `Increase5` | CWND += 5% |
| `Increase10` | CWND += 10% |
| `Maintain` | No change |
| `Decrease5` | CWND -= 5% |
| `Decrease10` | CWND -= 10% |
| `SlowStart` | Reset to initial CWND |

### Configuration

```rust
use oxidize_common::advanced_ml::{MultiAgentConfig, MultiAgentCoordinator};

let config = MultiAgentConfig {
    max_agents: 16,
    state_dim: 8,
    action_dim: 6,
    message_dim: 16,
    comm_rounds: 2,
    gamma: 0.99,
    learning_rate: 0.001,
    epsilon: 1.0,
    epsilon_decay: 0.995,
    epsilon_min: 0.01,
};

let coordinator = MultiAgentCoordinator::new(config);
```

### Usage

```rust
// Register agents (one per connection/flow)
coordinator.register_agent("flow_1".to_string());
coordinator.register_agent("flow_2".to_string());

// Update agent state
coordinator.update_state("flow_1", vec![rtt, loss, bw, ...]);

// Broadcast messages for coordination
coordinator.broadcast_message("flow_1", vec![my_cwnd, my_throughput, ...]);
coordinator.distribute_messages();

// Select action
let action = coordinator.select_action("flow_1");
apply_congestion_action(action);

// Record reward
let reward = calculate_cooperative_reward(
    agent_throughput,
    agent_latency,
    total_throughput,
    fairness_index,
);
coordinator.record_reward("flow_1", reward);
```

### Cooperative Reward

The reward function balances individual performance with global fairness:

```rust
reward = 0.7 * individual_reward + 0.3 * cooperative_reward

individual_reward = throughput_mbps - latency_penalty
cooperative_reward = total_throughput * fairness_index
```

## 3. A/B Testing Framework

Statistical experimentation for model deployment decisions.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ABTestingFramework                        │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌──────────────┐                 ┌──────────────┐         │
│   │   Control    │                 │  Treatment   │         │
│   │ (LSTM v1.0)  │                 │ (Transformer)│         │
│   └──────┬───────┘                 └──────┬───────┘         │
│          │                                │                  │
│          │  50% traffic                   │  50% traffic    │
│          │                                │                  │
│          └────────────────┬───────────────┘                  │
│                           │                                  │
│                           ▼                                  │
│                ┌──────────────────────┐                      │
│                │  T-Test Significance │                      │
│                │  p < 0.05 → Winner   │                      │
│                └──────────────────────┘                      │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Creating Experiments

```rust
use oxidize_common::advanced_ml::{
    ABTestConfig, ABTestingFramework, ModelVariant
};

let framework = ABTestingFramework::new();

let control = ModelVariant {
    name: "lstm_v1".to_string(),
    model_path: "/models/lstm_v1.onnx".to_string(),
    is_treatment: false,
};

let treatment = ModelVariant {
    name: "transformer_v1".to_string(),
    model_path: "/models/transformer_v1.onnx".to_string(),
    is_treatment: true,
};

let config = ABTestConfig {
    min_samples: 100,
    confidence_level: 0.95,
    treatment_fraction: 0.5,
    max_duration_secs: 86400,
    early_stopping: true,
};

let exp_id = framework.create_experiment(
    "lstm_vs_transformer".to_string(),
    control,
    treatment,
    config,
);
```

### Assigning Users

```rust
// Deterministic assignment based on user ID hash
let is_treatment = framework.get_assignment(&exp_id, &user_id)?;

// Get model path for this user
let model_path = framework.get_model_path(&exp_id, &user_id)?;
```

### Recording Results

```rust
use oxidize_common::advanced_ml::ABSample;

// Record metric (e.g., throughput, latency)
framework.record_sample(&exp_id, ABSample {
    is_treatment,
    metric_value: measured_throughput,
    timestamp_ms: now(),
});
```

### Getting Results

```rust
// Check if experiment has concluded
if let Some(result) = framework.get_result(&exp_id) {
    println!("Winner: {}", result.winner);
    println!("Lift: {:.2}%", result.lift_percent);
    println!("p-value: {:.4}", result.p_value);
}

// Or manually conclude
let result = framework.conclude_experiment(&exp_id)?;
```

## Unified Engine

All five features are available through the `AdvancedMlEngine`:

```rust
use oxidize_common::advanced_ml::AdvancedMlEngine;

// Client mode (no federation)
let engine = AdvancedMlEngine::new();

// Server mode (with federation)
let engine = AdvancedMlEngine::new_with_federation(initial_weights);

// Access components
engine.online_learner.add_sample(...);
engine.transformer.predict();
engine.multi_agent.select_action("agent1");
engine.ab_testing.create_experiment(...);

// Get unified stats
let stats = engine.stats();
```

## Performance Impact

All features are designed for minimal hot-path latency:

| Operation | Typical Latency |
|-----------|-----------------|
| Online learning sample add | <1µs |
| Online learning gradient step | ~1ms |
| Federated update submit | <10µs |
| Transformer inference | ~100µs |
| Multi-agent action selection | ~50µs |
| A/B test assignment | ~1µs |

Training and aggregation operations run asynchronously and never block the packet path.
