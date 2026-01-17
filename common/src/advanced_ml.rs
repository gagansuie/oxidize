//! Advanced ML Features for Oxidize
//!
//! This module implements 3 advanced ML features for scale-readiness:
//! 1. **Federated Learning** - Privacy-preserving aggregation with differential privacy
//! 2. **Multi-agent RL** - Distributed congestion control coordination (for multi-server)
//! 3. **A/B Testing Framework** - Model deployment experimentation
//!
//! ## Performance Characteristics
//!
//! | Feature | Latency Impact | Memory Overhead |
//! |---------|----------------|-----------------|
//! | Federated Learning | Async (no hot path) | ~1MB per client |
//! | Multi-agent RL | ~50µs per action | ~2MB per agent |
//! | A/B Testing | ~1µs assignment | ~100KB per experiment |

pub mod ab_testing;
pub mod federated_learning;
pub mod multi_agent_rl;

pub use ab_testing::*;
pub use federated_learning::*;
pub use multi_agent_rl::*;

// ============================================================================
// SHARED CONSTANTS
// ============================================================================

/// Maximum agents in multi-agent system
pub const MULTI_AGENT_MAX_AGENTS: usize = 16;
/// State dimension for each agent
pub const MULTI_AGENT_STATE_DIM: usize = 8;
/// Number of possible actions
pub const MULTI_AGENT_ACTION_DIM: usize = 6;
/// Message dimension for inter-agent communication
pub const MULTI_AGENT_MSG_DIM: usize = 16;

/// Minimum samples required for A/B test significance
pub const AB_TEST_MIN_SAMPLES: usize = 100;
/// Confidence level for A/B test (95%)
pub const AB_TEST_CONFIDENCE_LEVEL: f64 = 0.95;

// ============================================================================
// UNIFIED ADVANCED ML ENGINE
// ============================================================================

use std::sync::Arc;

/// Unified advanced ML engine that coordinates all 3 scale-ready features
pub struct AdvancedMlEngine {
    /// Federated learning coordinator (optional, server-side only)
    pub federated: Option<Arc<FederatedCoordinator>>,
    /// Multi-agent RL coordinator
    pub multi_agent: Arc<MultiAgentCoordinator>,
    /// A/B testing framework
    pub ab_testing: Arc<ABTestingFramework>,
}

impl AdvancedMlEngine {
    /// Create a new advanced ML engine with default configurations
    pub fn new() -> Self {
        Self {
            federated: None,
            multi_agent: Arc::new(MultiAgentCoordinator::new(MultiAgentConfig::default())),
            ab_testing: Arc::new(ABTestingFramework::new()),
        }
    }

    /// Create with federated learning enabled (for servers)
    pub fn new_with_federation(initial_weights: Vec<f64>) -> Self {
        Self {
            federated: Some(Arc::new(FederatedCoordinator::new(
                FederatedConfig::default(),
                initial_weights,
            ))),
            multi_agent: Arc::new(MultiAgentCoordinator::new(MultiAgentConfig::default())),
            ab_testing: Arc::new(ABTestingFramework::new()),
        }
    }

    /// Get comprehensive statistics
    pub fn stats(&self) -> AdvancedMlStats {
        AdvancedMlStats {
            federated: self.federated.as_ref().map(|f| f.stats()),
            multi_agent: self.multi_agent.stats(),
            ab_testing_experiments: self.ab_testing.list_experiments().len(),
        }
    }
}

impl Default for AdvancedMlEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Combined statistics for all advanced ML features
#[derive(Debug, Clone)]
pub struct AdvancedMlStats {
    pub federated: Option<FederatedLearningStats>,
    pub multi_agent: MultiAgentStats,
    pub ab_testing_experiments: usize,
}
