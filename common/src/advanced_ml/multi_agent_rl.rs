//! Multi-agent RL for Congestion Control
//!
//! Implements distributed reinforcement learning with:
//! - Decentralized execution with centralized training (CTDE)
//! - Inter-agent communication via message passing
//! - Cooperative reward shaping
//! - Epsilon-greedy exploration with decay

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};

#[cfg(feature = "ai")]
use candle_core::{DType, Device, Result as CandleResult, Tensor};
#[cfg(feature = "ai")]
use candle_nn::{linear, Linear, Module, VarBuilder, VarMap};

use super::{
    MULTI_AGENT_ACTION_DIM, MULTI_AGENT_MAX_AGENTS, MULTI_AGENT_MSG_DIM, MULTI_AGENT_STATE_DIM,
};

/// Multi-agent RL configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAgentConfig {
    pub max_agents: usize,
    pub state_dim: usize,
    pub action_dim: usize,
    pub message_dim: usize,
    pub comm_rounds: usize,
    pub gamma: f64,
    pub learning_rate: f64,
    pub epsilon: f64,
    pub epsilon_decay: f64,
    pub epsilon_min: f64,
}

impl Default for MultiAgentConfig {
    fn default() -> Self {
        Self {
            max_agents: MULTI_AGENT_MAX_AGENTS,
            state_dim: MULTI_AGENT_STATE_DIM,
            action_dim: MULTI_AGENT_ACTION_DIM,
            message_dim: MULTI_AGENT_MSG_DIM,
            comm_rounds: 2,
            gamma: 0.99,
            learning_rate: 0.001,
            epsilon: 1.0,
            epsilon_decay: 0.995,
            epsilon_min: 0.01,
        }
    }
}

/// Agent state in multi-agent system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub agent_id: String,
    pub local_state: Vec<f64>,
    pub received_messages: Vec<AgentMessage>,
    pub last_action: usize,
    pub cumulative_reward: f64,
}

/// Message between agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessage {
    pub from_agent: String,
    pub content: Vec<f64>,
    pub timestamp_ms: u64,
}

/// Multi-agent Q-Network for distributed congestion control
#[cfg(feature = "ai")]
pub struct MultiAgentQNetwork {
    state_encoder: Linear,
    message_encoder: Linear,
    comm_layer: Linear,
    q_head: Linear,
    #[allow(dead_code)]
    config: MultiAgentConfig,
}

#[cfg(feature = "ai")]
impl MultiAgentQNetwork {
    pub fn new(config: MultiAgentConfig, vb: VarBuilder) -> CandleResult<Self> {
        let hidden_dim = 128;
        Ok(Self {
            state_encoder: linear(config.state_dim, hidden_dim, vb.pp("state_enc"))?,
            message_encoder: linear(
                config.message_dim * config.max_agents,
                hidden_dim,
                vb.pp("msg_enc"),
            )?,
            comm_layer: linear(hidden_dim, config.message_dim, vb.pp("comm"))?,
            q_head: linear(hidden_dim * 2, config.action_dim, vb.pp("q_head"))?,
            config,
        })
    }

    pub fn forward(
        &self,
        local_state: &Tensor,
        aggregated_messages: &Tensor,
    ) -> CandleResult<Tensor> {
        let state_enc = self.state_encoder.forward(local_state)?.relu()?;
        let msg_enc = self.message_encoder.forward(aggregated_messages)?.relu()?;
        let combined = Tensor::cat(&[&state_enc, &msg_enc], 1)?;
        self.q_head.forward(&combined)
    }

    pub fn generate_message(&self, local_state: &Tensor) -> CandleResult<Tensor> {
        let state_enc = self.state_encoder.forward(local_state)?.relu()?;
        self.comm_layer.forward(&state_enc)
    }
}

/// Multi-agent coordinator for distributed congestion control
pub struct MultiAgentCoordinator {
    config: MultiAgentConfig,
    agents: RwLock<HashMap<String, AgentState>>,
    message_buffer: RwLock<Vec<AgentMessage>>,
    epsilon: RwLock<f64>,
    total_decisions: AtomicU64,
    #[cfg(feature = "ai")]
    q_network: Option<MultiAgentQNetwork>,
    #[cfg(feature = "ai")]
    device: Device,
}

impl MultiAgentCoordinator {
    pub fn new(config: MultiAgentConfig) -> Self {
        let epsilon = config.epsilon;
        Self {
            config,
            agents: RwLock::new(HashMap::new()),
            message_buffer: RwLock::new(Vec::new()),
            epsilon: RwLock::new(epsilon),
            total_decisions: AtomicU64::new(0),
            #[cfg(feature = "ai")]
            q_network: None,
            #[cfg(feature = "ai")]
            device: Device::Cpu,
        }
    }

    #[cfg(feature = "ai")]
    pub fn load_model(&mut self, var_map: &VarMap) -> CandleResult<()> {
        let vb = VarBuilder::from_varmap(var_map, DType::F32, &self.device);
        self.q_network = Some(MultiAgentQNetwork::new(self.config.clone(), vb)?);
        Ok(())
    }

    /// Register a new agent
    pub fn register_agent(&self, agent_id: String) {
        if let Ok(mut agents) = self.agents.write() {
            if agents.len() < self.config.max_agents && !agents.contains_key(&agent_id) {
                agents.insert(
                    agent_id.clone(),
                    AgentState {
                        agent_id,
                        local_state: vec![0.0; self.config.state_dim],
                        received_messages: Vec::new(),
                        last_action: 2,
                        cumulative_reward: 0.0,
                    },
                );
            }
        }
    }

    /// Unregister an agent
    pub fn unregister_agent(&self, agent_id: &str) {
        if let Ok(mut agents) = self.agents.write() {
            agents.remove(agent_id);
        }
    }

    /// Update agent's local state
    pub fn update_state(&self, agent_id: &str, state: Vec<f64>) {
        if let Ok(mut agents) = self.agents.write() {
            if let Some(agent) = agents.get_mut(agent_id) {
                agent.local_state = state;
            }
        }
    }

    /// Broadcast message from an agent
    pub fn broadcast_message(&self, from_agent: &str, content: Vec<f64>) {
        let msg = AgentMessage {
            from_agent: from_agent.to_string(),
            content,
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        };

        if let Ok(mut buffer) = self.message_buffer.write() {
            buffer.push(msg);
        }
    }

    /// Distribute messages to agents
    pub fn distribute_messages(&self) {
        let messages = {
            let mut buffer = match self.message_buffer.write() {
                Ok(b) => b,
                Err(_) => return,
            };
            std::mem::take(&mut *buffer)
        };

        if let Ok(mut agents) = self.agents.write() {
            for (agent_id, agent) in agents.iter_mut() {
                agent.received_messages = messages
                    .iter()
                    .filter(|m| &m.from_agent != agent_id)
                    .cloned()
                    .collect();
            }
        }
    }

    /// Select action for an agent
    pub fn select_action(&self, agent_id: &str) -> usize {
        let epsilon = self.epsilon.read().map(|e| *e).unwrap_or(0.1);

        let rand_val = {
            let seed = self.total_decisions.fetch_add(1, Ordering::Relaxed);
            ((seed.wrapping_mul(1103515245).wrapping_add(12345)) as f64) / u64::MAX as f64
        };

        if rand_val < epsilon {
            let action_seed = self.total_decisions.load(Ordering::Relaxed);
            return (action_seed as usize) % self.config.action_dim;
        }

        #[cfg(feature = "ai")]
        if let Some(ref q_network) = self.q_network {
            if let Ok(agents) = self.agents.read() {
                if let Some(agent) = agents.get(agent_id) {
                    if let Ok(action) = self.compute_best_action(q_network, agent) {
                        return action;
                    }
                }
            }
        }

        self.heuristic_action(agent_id)
    }

    #[cfg(feature = "ai")]
    fn compute_best_action(
        &self,
        q_network: &MultiAgentQNetwork,
        agent: &AgentState,
    ) -> CandleResult<usize> {
        let state_f32: Vec<f32> = agent.local_state.iter().map(|&x| x as f32).collect();
        let state_tensor = Tensor::from_vec(state_f32, (1, self.config.state_dim), &self.device)?;

        let mut msg_vec = vec![0.0f32; self.config.message_dim * self.config.max_agents];
        for (i, msg) in agent
            .received_messages
            .iter()
            .take(self.config.max_agents)
            .enumerate()
        {
            for (j, &val) in msg.content.iter().take(self.config.message_dim).enumerate() {
                msg_vec[i * self.config.message_dim + j] = val as f32;
            }
        }
        let msg_tensor = Tensor::from_vec(
            msg_vec,
            (1, self.config.message_dim * self.config.max_agents),
            &self.device,
        )?;

        let q_values = q_network.forward(&state_tensor, &msg_tensor)?;
        let q_vec = q_values.to_vec2::<f32>()?;

        let action = q_vec[0]
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i)
            .unwrap_or(2);

        Ok(action)
    }

    fn heuristic_action(&self, agent_id: &str) -> usize {
        if let Ok(agents) = self.agents.read() {
            if let Some(agent) = agents.get(agent_id) {
                let loss_rate = agent.local_state.get(3).copied().unwrap_or(0.0);
                let buffer_occ = agent.local_state.get(7).copied().unwrap_or(0.5);

                if loss_rate > 0.1 || buffer_occ > 0.8 {
                    return 4; // Decrease 10%
                } else if loss_rate > 0.05 || buffer_occ > 0.6 {
                    return 3; // Decrease 5%
                } else if loss_rate < 0.01 && buffer_occ < 0.3 {
                    return 1; // Increase 10%
                } else if loss_rate < 0.02 && buffer_occ < 0.5 {
                    return 0; // Increase 5%
                }
            }
        }
        2 // Maintain
    }

    /// Record reward and update epsilon
    pub fn record_reward(&self, agent_id: &str, reward: f64) {
        if let Ok(mut agents) = self.agents.write() {
            if let Some(agent) = agents.get_mut(agent_id) {
                agent.cumulative_reward += reward;
                agent.last_action = self.heuristic_action(agent_id);
            }
        }

        if let Ok(mut epsilon) = self.epsilon.write() {
            *epsilon = (*epsilon * self.config.epsilon_decay).max(self.config.epsilon_min);
        }
    }

    /// Get number of registered agents
    pub fn num_agents(&self) -> usize {
        self.agents.read().map(|a| a.len()).unwrap_or(0)
    }

    /// Get multi-agent stats
    pub fn stats(&self) -> MultiAgentStats {
        let (num_agents, total_reward) = self
            .agents
            .read()
            .map(|a| {
                (
                    a.len(),
                    a.values().map(|s| s.cumulative_reward).sum::<f64>(),
                )
            })
            .unwrap_or((0, 0.0));

        MultiAgentStats {
            num_agents,
            total_decisions: self.total_decisions.load(Ordering::Relaxed),
            epsilon: self.epsilon.read().map(|e| *e).unwrap_or(0.0),
            total_reward,
        }
    }

    pub fn is_loaded(&self) -> bool {
        #[cfg(feature = "ai")]
        return self.q_network.is_some();
        #[cfg(not(feature = "ai"))]
        return false;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAgentStats {
    pub num_agents: usize,
    pub total_decisions: u64,
    pub epsilon: f64,
    pub total_reward: f64,
}

/// Calculate cooperative reward for multi-agent system
pub fn calculate_cooperative_reward(
    agent_throughput: f64,
    agent_latency: f64,
    total_throughput: f64,
    fairness_index: f64,
) -> f64 {
    let individual = agent_throughput / 1_000_000.0 - agent_latency / 100_000.0;
    let cooperative = total_throughput / 1_000_000.0 * fairness_index;
    0.7 * individual + 0.3 * cooperative
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multi_agent_coordinator() {
        let config = MultiAgentConfig::default();
        let coord = MultiAgentCoordinator::new(config);

        coord.register_agent("agent1".to_string());
        coord.register_agent("agent2".to_string());

        assert_eq!(coord.num_agents(), 2);

        coord.update_state("agent1", vec![0.0; 8]);
        let action = coord.select_action("agent1");
        assert!(action < 6);
    }

    #[test]
    fn test_cooperative_reward() {
        let reward = calculate_cooperative_reward(100_000_000.0, 50_000.0, 200_000_000.0, 0.9);
        assert!(reward > 0.0);
    }
}
