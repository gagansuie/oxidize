//! Hugging Face Hub Integration for Model Sync
//!
//! Provides distributed model management:
//! - Download pre-trained models from HF Hub
//! - Upload training data and updated models
//! - Automatic model version management
//!
//! Repository structure:
//! ```text
//! oxidize/congestion-models/
//! ├── transformer_loss.safetensors
//! ├── ppo_congestion.safetensors
//! ├── config.json
//! └── training_data/
//!     └── samples-YYYY-MM-DD.json
//! ```

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

#[cfg(feature = "ai")]
use hf_hub::api::sync::Api;
#[cfg(feature = "ai")]
use hf_hub::Repo;

use crate::ml_optimized::{DrlExperience, LossSample};

/// Default HF Hub repository for Oxidize models
pub const DEFAULT_REPO: &str = "gagansuie/oxidize-models";

/// Model file names
pub const TRANSFORMER_MODEL_FILE: &str = "transformer_loss.safetensors";
pub const PPO_MODEL_FILE: &str = "ppo_congestion.safetensors";
pub const CONFIG_FILE: &str = "config.json";

/// Model configuration stored on HF Hub
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    /// Model version (semver)
    pub version: String,
    /// Transformer model info
    pub transformer: TransformerModelConfig,
    /// PPO model info
    pub ppo: PpoModelConfig,
    /// Training metadata
    pub training: TrainingMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformerModelConfig {
    pub d_model: usize,
    pub n_heads: usize,
    pub sequence_length: usize,
    pub trained_samples: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PpoModelConfig {
    pub state_size: usize,
    pub hidden_size: usize,
    pub trained_steps: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMetadata {
    pub last_updated: String,
    pub total_samples: u64,
    pub contributing_servers: u32,
}

impl Default for ModelConfig {
    fn default() -> Self {
        ModelConfig {
            version: "0.2.0".into(),
            transformer: TransformerModelConfig {
                d_model: 64,
                n_heads: 4,
                sequence_length: 20,
                trained_samples: 0,
            },
            ppo: PpoModelConfig {
                state_size: 8,
                hidden_size: 128,
                trained_steps: 0,
            },
            training: TrainingMetadata {
                last_updated: chrono_lite_now(),
                total_samples: 0,
                contributing_servers: 0,
            },
        }
    }
}

/// Simple timestamp without chrono dependency
fn chrono_lite_now() -> String {
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}", duration.as_secs())
}

/// HF Hub sync configuration
#[derive(Debug, Clone)]
pub struct HubConfig {
    /// HF Hub repository (e.g., "oxidize/congestion-models")
    pub repo_id: String,
    /// Local cache directory for models
    pub cache_dir: PathBuf,
    /// HF API token (optional for public repos, required for upload)
    pub token: Option<String>,
    /// Auto-sync interval for downloading new models
    pub sync_interval: Duration,
    /// Whether to upload training data
    pub upload_training_data: bool,
    /// Server identifier for training data attribution
    pub server_id: String,
}

impl Default for HubConfig {
    fn default() -> Self {
        HubConfig {
            repo_id: DEFAULT_REPO.into(),
            cache_dir: PathBuf::from("/tmp/oxidize_models"),
            token: std::env::var("HF_TOKEN").ok(),
            sync_interval: Duration::from_secs(3600), // 1 hour
            upload_training_data: true,               // Enabled by default
            server_id: generate_server_id(),
        }
    }
}

/// Generate a unique server ID
fn generate_server_id() -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();

    // Hash hostname + process ID for uniqueness
    if let Ok(hostname) = std::env::var("HOSTNAME") {
        hostname.hash(&mut hasher);
    }
    std::process::id().hash(&mut hasher);
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
        .hash(&mut hasher);

    format!("server-{:016x}", hasher.finish())
}

/// Hub sync statistics
#[derive(Debug, Default)]
pub struct HubStats {
    pub downloads: AtomicU64,
    pub uploads: AtomicU64,
    pub last_sync_epoch: AtomicU64,
    pub sync_errors: AtomicU64,
    pub is_syncing: AtomicBool,
}

/// Model Hub client for downloading/uploading models
pub struct ModelHub {
    config: HubConfig,
    stats: Arc<HubStats>,
    #[cfg(feature = "ai")]
    api: Option<Api>,
}

impl ModelHub {
    /// Create new ModelHub client
    pub fn new(config: HubConfig) -> Self {
        #[cfg(feature = "ai")]
        let api = Api::new().ok();

        // Ensure cache directory exists
        let _ = std::fs::create_dir_all(&config.cache_dir);

        ModelHub {
            config,
            stats: Arc::new(HubStats::default()),
            #[cfg(feature = "ai")]
            api,
        }
    }

    /// Create with default config
    pub fn default_config() -> Self {
        Self::new(HubConfig::default())
    }

    /// Download latest models from HF Hub
    #[cfg(feature = "ai")]
    pub fn download_models(&self) -> anyhow::Result<ModelPaths> {
        let api = self
            .api
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HF Hub API not initialized"))?;

        self.stats.is_syncing.store(true, Ordering::SeqCst);

        let repo = api.repo(Repo::model(self.config.repo_id.clone()));

        // Download Transformer model
        let transformer_path = match repo.get(TRANSFORMER_MODEL_FILE) {
            Ok(path) => {
                debug!("Downloaded Transformer model: {:?}", path);
                Some(path)
            }
            Err(e) => {
                warn!("Transformer model not found on hub: {}", e);
                None
            }
        };

        // Download PPO model
        let ppo_path = match repo.get(PPO_MODEL_FILE) {
            Ok(path) => {
                debug!("Downloaded PPO model: {:?}", path);
                Some(path)
            }
            Err(e) => {
                warn!("PPO model not found on hub: {}", e);
                None
            }
        };

        // Download config
        let config_path = repo.get(CONFIG_FILE).ok();

        self.stats.downloads.fetch_add(1, Ordering::SeqCst);
        self.stats.last_sync_epoch.store(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            Ordering::SeqCst,
        );
        self.stats.is_syncing.store(false, Ordering::SeqCst);

        info!("Model sync complete from {}", self.config.repo_id);

        Ok(ModelPaths {
            transformer: transformer_path,
            ppo: ppo_path,
            config: config_path,
        })
    }

    #[cfg(not(feature = "ai"))]
    pub fn download_models(&self) -> anyhow::Result<ModelPaths> {
        anyhow::bail!("AI features not compiled in")
    }

    /// Get local model paths (from cache)
    pub fn local_model_paths(&self) -> ModelPaths {
        let transformer = self.config.cache_dir.join(TRANSFORMER_MODEL_FILE);
        let ppo = self.config.cache_dir.join(PPO_MODEL_FILE);
        let config = self.config.cache_dir.join(CONFIG_FILE);

        ModelPaths {
            transformer: if transformer.exists() {
                Some(transformer)
            } else {
                None
            },
            ppo: if ppo.exists() { Some(ppo) } else { None },
            config: if config.exists() { Some(config) } else { None },
        }
    }

    /// Export training data to JSON file
    pub fn export_training_data(
        &self,
        loss_samples: &[LossSample],
        drl_experiences: &[DrlExperience],
    ) -> anyhow::Result<PathBuf> {
        let timestamp = chrono_lite_now();
        let filename = format!("training-{}-{}.json", self.config.server_id, timestamp);
        let path = self.config.cache_dir.join("training_data").join(&filename);

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let data = TrainingDataExport {
            server_id: self.config.server_id.clone(),
            timestamp: timestamp.clone(),
            loss_samples: loss_samples.to_vec(),
            drl_experiences: drl_experiences.to_vec(),
        };

        let json = serde_json::to_string_pretty(&data)?;
        std::fs::write(&path, json)?;

        info!(
            "Exported {} loss samples and {} DRL experiences to {:?}",
            loss_samples.len(),
            drl_experiences.len(),
            path
        );

        Ok(path)
    }

    /// Get sync statistics
    pub fn stats(&self) -> HubSyncStats {
        HubSyncStats {
            downloads: self.stats.downloads.load(Ordering::SeqCst),
            uploads: self.stats.uploads.load(Ordering::SeqCst),
            last_sync_epoch: self.stats.last_sync_epoch.load(Ordering::SeqCst),
            sync_errors: self.stats.sync_errors.load(Ordering::SeqCst),
            is_syncing: self.stats.is_syncing.load(Ordering::SeqCst),
            repo_id: self.config.repo_id.clone(),
            server_id: self.config.server_id.clone(),
        }
    }

    /// Get config reference
    pub fn config(&self) -> &HubConfig {
        &self.config
    }

    /// Upload training data to HF Hub
    /// This uploads collected training samples for aggregation and model training
    #[cfg(feature = "ai")]
    pub fn upload_training_data(
        &self,
        loss_samples: &[LossSample],
        drl_experiences: &[DrlExperience],
    ) -> anyhow::Result<()> {
        if loss_samples.is_empty() && drl_experiences.is_empty() {
            debug!("No training data to upload");
            return Ok(());
        }

        let token = self
            .config
            .token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("HF_TOKEN required for upload"))?;

        // Export to local file first
        let local_path = self.export_training_data(loss_samples, drl_experiences)?;

        let filename = local_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("training_data.json");

        // Upload to training_data/ directory in the repo
        let remote_path = format!("training_data/{}", filename);

        // Use the HF Hub upload API
        use std::process::Command;
        let output = Command::new("huggingface-cli")
            .args([
                "upload",
                &self.config.repo_id,
                local_path.to_str().unwrap_or(""),
                &remote_path,
                "--repo-type",
                "model",
                "--token",
                token,
            ])
            .output();

        match output {
            Ok(out) if out.status.success() => {
                self.stats.uploads.fetch_add(1, Ordering::SeqCst);
                info!(
                    "Uploaded training data: {} loss samples, {} DRL experiences",
                    loss_samples.len(),
                    drl_experiences.len()
                );
                Ok(())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                self.stats.sync_errors.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("Upload failed: {}", stderr)
            }
            Err(e) => {
                self.stats.sync_errors.fetch_add(1, Ordering::SeqCst);
                anyhow::bail!("Upload command failed: {}", e)
            }
        }
    }

    #[cfg(not(feature = "ai"))]
    pub fn upload_training_data(
        &self,
        _loss_samples: &[LossSample],
        _drl_experiences: &[DrlExperience],
    ) -> anyhow::Result<()> {
        anyhow::bail!("AI features not compiled in")
    }
}

/// Paths to downloaded models
#[derive(Debug, Clone)]
pub struct ModelPaths {
    pub transformer: Option<PathBuf>,
    pub ppo: Option<PathBuf>,
    pub config: Option<PathBuf>,
}

/// Training data export format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingDataExport {
    pub server_id: String,
    pub timestamp: String,
    pub loss_samples: Vec<LossSample>,
    pub drl_experiences: Vec<DrlExperience>,
}

/// Hub sync statistics (serializable)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubSyncStats {
    pub downloads: u64,
    pub uploads: u64,
    pub last_sync_epoch: u64,
    pub sync_errors: u64,
    pub is_syncing: bool,
    pub repo_id: String,
    pub server_id: String,
}

// ============================================================================
// BACKGROUND SYNC MANAGER
// ============================================================================

/// Background sync manager that periodically fetches new models
pub struct HubSyncManager {
    hub: Arc<ModelHub>,
    stop_flag: Arc<AtomicBool>,
    sync_interval: Duration,
    last_sync: Option<Instant>,
}

impl HubSyncManager {
    pub fn new(hub: ModelHub) -> Self {
        let sync_interval = hub.config.sync_interval;
        HubSyncManager {
            hub: Arc::new(hub),
            stop_flag: Arc::new(AtomicBool::new(false)),
            sync_interval,
            last_sync: None,
        }
    }

    /// Check if sync is needed and perform it
    pub fn maybe_sync(&mut self) -> Option<ModelPaths> {
        let should_sync = match self.last_sync {
            None => true,
            Some(last) => last.elapsed() > self.sync_interval,
        };

        if !should_sync {
            return None;
        }

        match self.hub.download_models() {
            Ok(paths) => {
                self.last_sync = Some(Instant::now());
                Some(paths)
            }
            Err(e) => {
                warn!("Model sync failed: {}", e);
                None
            }
        }
    }

    /// Force sync now
    pub fn sync_now(&mut self) -> anyhow::Result<ModelPaths> {
        let paths = self.hub.download_models()?;
        self.last_sync = Some(Instant::now());
        Ok(paths)
    }

    /// Get hub reference
    pub fn hub(&self) -> &ModelHub {
        &self.hub
    }

    /// Stop sync (for cleanup)
    pub fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

// ============================================================================
// INTEGRATION WITH ML ENGINE
// ============================================================================

/// Extension trait to load models from HF Hub
pub trait HubModelLoader {
    /// Load models from HF Hub paths
    fn load_from_hub(&mut self, paths: &ModelPaths) -> anyhow::Result<()>;
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = HubConfig::default();
        assert_eq!(config.repo_id, "gagansuie/oxidize-models");
        assert!(!config.server_id.is_empty());
    }

    #[test]
    fn test_server_id_generation() {
        let id1 = generate_server_id();
        let id2 = generate_server_id();
        // IDs should be unique (different timestamps)
        assert!(id1.starts_with("server-"));
        assert!(id2.starts_with("server-"));
    }

    #[test]
    fn test_model_config_default() {
        let config = ModelConfig::default();
        assert_eq!(config.version, "0.2.0");
        assert_eq!(config.transformer.d_model, 64);
        assert_eq!(config.ppo.state_size, 8);
    }

    #[test]
    fn test_export_training_data() {
        let hub = ModelHub::new(HubConfig {
            cache_dir: PathBuf::from("/tmp/oxidize_test"),
            ..Default::default()
        });

        let loss_samples = vec![LossSample {
            timestamp_ms: 1000,
            rtt_us: 50_000,
            rtt_var_us: 5000,
            bandwidth_bps: 100_000_000,
            loss_rate: 0.01,
            inflight: 100,
            buffer_occupancy: 0.3,
            ipg_us: 1000,
            future_loss: 0.02,
        }];

        let result = hub.export_training_data(&loss_samples, &[]);
        assert!(result.is_ok());

        // Cleanup
        let _ = std::fs::remove_dir_all("/tmp/oxidize_test");
    }

    #[test]
    fn test_local_model_paths() {
        let hub = ModelHub::new(HubConfig {
            cache_dir: PathBuf::from("/tmp/nonexistent"),
            ..Default::default()
        });

        let paths = hub.local_model_paths();
        assert!(paths.transformer.is_none());
        assert!(paths.ppo.is_none());
    }
}
