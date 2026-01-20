//! Oxidize ML Training Binary
//!
//! CLI tool for training ML models from collected data.
//!
//! Usage:
//!   oxidize-train --input ./training_data --output ./models --epochs 100
//!
//! Models trained (SafeTensors format):
//! - Transformer Loss Predictor (transformer_loss.safetensors)
//! - PPO Congestion Controller (ppo_congestion.safetensors)

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use oxidize_common::ml_optimized::{
    CompressionSample, DrlExperience, LossSample, PathSelectionSample,
};
use oxidize_common::ml_training::{PpoTrainer, TransformerTrainer};

/// Oxidize ML Training CLI
#[derive(Parser, Debug)]
#[command(name = "oxidize-train")]
#[command(about = "Train ML models for Oxidize VPN optimization")]
#[command(version)]
struct Args {
    /// Input directory containing training data JSON files
    #[arg(short, long, default_value = "./training_data")]
    input: PathBuf,

    /// Output directory for trained models
    #[arg(short, long, default_value = "./models")]
    output: PathBuf,

    /// Number of training epochs for Transformer
    #[arg(long, default_value = "100")]
    transformer_epochs: usize,

    /// Number of training steps for PPO
    #[arg(long, default_value = "1000")]
    ppo_steps: usize,

    /// Generate synthetic training data if no real data exists
    #[arg(long)]
    generate_synthetic: bool,

    /// Number of synthetic samples to generate
    #[arg(long, default_value = "10000")]
    synthetic_samples: usize,

    /// Minimum samples required to train (skip if fewer)
    #[arg(long, default_value = "100")]
    min_samples: usize,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

/// Training data container
#[derive(Debug, Default, Serialize, Deserialize)]
struct TrainingData {
    loss_samples: Vec<LossSample>,
    drl_experiences: Vec<DrlExperience>,
    compression_samples: Vec<CompressionSample>,
    path_samples: Vec<PathSelectionSample>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let filter = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    info!("Oxidize ML Training");
    info!("Input: {:?}", args.input);
    info!("Output: {:?}", args.output);

    // Create output directory
    fs::create_dir_all(&args.output)?;

    // Load or generate training data
    let mut data = load_training_data(&args.input)?;

    if args.generate_synthetic
        || (data.loss_samples.len() < args.min_samples
            && data.drl_experiences.len() < args.min_samples)
    {
        info!("Generating {} synthetic samples...", args.synthetic_samples);
        generate_synthetic_data(&mut data, args.synthetic_samples);
    }

    info!(
        "Training data: {} loss samples, {} DRL experiences, {} compression samples, {} path samples",
        data.loss_samples.len(),
        data.drl_experiences.len(),
        data.compression_samples.len(),
        data.path_samples.len()
    );

    // Train Transformer Loss Predictor
    if data.loss_samples.len() >= args.min_samples {
        train_transformer(&data.loss_samples, &args.output, args.transformer_epochs)?;
    } else {
        warn!(
            "Skipping Transformer training: {} samples < {} minimum",
            data.loss_samples.len(),
            args.min_samples
        );
    }

    // Train PPO Congestion Controller
    if data.drl_experiences.len() >= args.min_samples {
        train_ppo(&data.drl_experiences, &args.output, args.ppo_steps)?;
    } else {
        warn!(
            "Skipping PPO training: {} experiences < {} minimum",
            data.drl_experiences.len(),
            args.min_samples
        );
    }

    // Update config.json with training stats
    update_config(&args.output, &data)?;

    info!("Training complete!");
    Ok(())
}

/// Load training data from JSON files in directory
fn load_training_data(input_dir: &Path) -> Result<TrainingData> {
    let mut data = TrainingData::default();

    if !input_dir.exists() {
        info!("Input directory does not exist, will use synthetic data");
        return Ok(data);
    }

    // Load loss samples
    let loss_path = input_dir.join("loss_samples.json");
    if loss_path.exists() {
        let content = fs::read_to_string(&loss_path)?;
        data.loss_samples =
            serde_json::from_str(&content).context("Failed to parse loss_samples.json")?;
        info!("Loaded {} loss samples", data.loss_samples.len());
    }

    // Load DRL experiences
    let drl_path = input_dir.join("drl_experiences.json");
    if drl_path.exists() {
        let content = fs::read_to_string(&drl_path)?;
        data.drl_experiences =
            serde_json::from_str(&content).context("Failed to parse drl_experiences.json")?;
        info!("Loaded {} DRL experiences", data.drl_experiences.len());
    }

    // Load compression samples
    let comp_path = input_dir.join("compression_samples.json");
    if comp_path.exists() {
        let content = fs::read_to_string(&comp_path)?;
        data.compression_samples =
            serde_json::from_str(&content).context("Failed to parse compression_samples.json")?;
        info!(
            "Loaded {} compression samples",
            data.compression_samples.len()
        );
    }

    // Load path selection samples
    let path_path = input_dir.join("path_selection_samples.json");
    if path_path.exists() {
        let content = fs::read_to_string(&path_path)?;
        data.path_samples = serde_json::from_str(&content)
            .context("Failed to parse path_selection_samples.json")?;
        info!("Loaded {} path selection samples", data.path_samples.len());
    }

    // Also try to load from individual server uploads
    for entry in fs::read_dir(input_dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json") {
            let name = path.file_stem().unwrap_or_default().to_string_lossy();

            // Skip already processed files
            if name == "loss_samples"
                || name == "drl_experiences"
                || name == "compression_samples"
                || name == "path_selection_samples"
            {
                continue;
            }

            // Try to parse as loss samples
            if name.contains("loss") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(samples) = serde_json::from_str::<Vec<LossSample>>(&content) {
                        info!("Loaded {} loss samples from {}", samples.len(), name);
                        data.loss_samples.extend(samples);
                    }
                }
            }
            // Try to parse as DRL experiences
            else if name.contains("drl") || name.contains("experience") {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(experiences) = serde_json::from_str::<Vec<DrlExperience>>(&content) {
                        info!("Loaded {} DRL experiences from {}", experiences.len(), name);
                        data.drl_experiences.extend(experiences);
                    }
                }
            }
        }
    }

    Ok(data)
}

/// Generate synthetic training data for initial model training
fn generate_synthetic_data(data: &mut TrainingData, count: usize) {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Generate loss samples with realistic network patterns
    for i in 0..count {
        // Simulate different network conditions
        let condition = i % 4;
        let (base_rtt, base_loss, base_bw) = match condition {
            0 => (20_000u64, 0.001f32, 100_000_000u64), // Good network
            1 => (50_000, 0.01, 50_000_000),            // Medium network
            2 => (100_000, 0.05, 20_000_000),           // Poor network
            _ => (200_000, 0.1, 10_000_000),            // Bad network
        };

        // Add noise
        let rtt = base_rtt + rng.gen_range(0..base_rtt / 4);
        let loss = (base_loss + rng.gen_range(-0.005..0.02)).clamp(0.0, 1.0);
        let bw = base_bw + rng.gen_range(0..base_bw / 4);

        // Future loss is correlated with current conditions
        let future_loss = if loss > 0.05 {
            (loss + rng.gen_range(0.0..0.1)).min(1.0)
        } else if rtt > 100_000 {
            rng.gen_range(0.01..0.05)
        } else {
            rng.gen_range(0.0..0.02)
        };

        data.loss_samples.push(LossSample {
            timestamp_ms: i as u64 * 10,
            rtt_us: rtt,
            rtt_var_us: rng.gen_range(1000..rtt / 4),
            bandwidth_bps: bw,
            loss_rate: loss,
            inflight: rng.gen_range(10..500),
            buffer_occupancy: rng.gen_range(0.1..0.9),
            ipg_us: rng.gen_range(100..5000),
            future_loss,
        });
    }

    // Generate DRL experiences
    for i in 0..count {
        use oxidize_common::ml_optimized::{DrlReward, DrlState};

        let state = DrlState {
            rtt_norm: rng.gen_range(0.0..1.0),
            rtt_gradient: rng.gen_range(-0.2..0.2),
            throughput_norm: rng.gen_range(0.2..1.0),
            loss_rate: rng.gen_range(0.0..0.1),
            cwnd_norm: rng.gen_range(0.3..0.8),
            inflight_norm: rng.gen_range(0.1..0.7),
            buffer_occupancy: rng.gen_range(0.1..0.8),
            time_in_state: rng.gen_range(0.0..1.0),
        };

        let action = rng.gen_range(0..6);

        // Reward depends on action appropriateness
        let reward_value = if state.loss_rate > 0.05 {
            // High loss - decrease actions are good
            if action >= 3 {
                rng.gen_range(0.5..1.0)
            } else {
                rng.gen_range(-0.5..0.2)
            }
        } else if state.throughput_norm < 0.5 {
            // Low throughput - increase actions are good
            if action <= 1 {
                rng.gen_range(0.5..1.0)
            } else {
                rng.gen_range(0.0..0.5)
            }
        } else {
            // Good state - maintain is good
            if action == 2 {
                rng.gen_range(0.6..1.0)
            } else {
                rng.gen_range(0.2..0.6)
            }
        };

        let reward = DrlReward {
            throughput_reward: reward_value * 0.4,
            latency_penalty: if state.rtt_norm > 0.5 { -0.2 } else { 0.0 },
            loss_penalty: -state.loss_rate * 2.0,
            total: reward_value,
        };

        let next_state = DrlState {
            rtt_norm: (state.rtt_norm + rng.gen_range(-0.1..0.1)).clamp(0.0, 1.0),
            rtt_gradient: rng.gen_range(-0.1..0.1),
            throughput_norm: (state.throughput_norm + rng.gen_range(-0.1..0.1)).clamp(0.0, 1.0),
            loss_rate: (state.loss_rate + rng.gen_range(-0.02..0.02)).clamp(0.0, 1.0),
            cwnd_norm: (state.cwnd_norm + rng.gen_range(-0.1..0.1)).clamp(0.0, 1.0),
            inflight_norm: (state.inflight_norm + rng.gen_range(-0.1..0.1)).clamp(0.0, 1.0),
            buffer_occupancy: (state.buffer_occupancy + rng.gen_range(-0.1..0.1)).clamp(0.0, 1.0),
            time_in_state: rng.gen_range(0.0..1.0),
        };

        data.drl_experiences.push(DrlExperience {
            state,
            action,
            reward,
            next_state,
            done: i % 100 == 99, // Episode ends every 100 steps
        });
    }

    info!(
        "Generated {} synthetic loss samples and {} DRL experiences",
        data.loss_samples.len(),
        data.drl_experiences.len()
    );
}

/// Train Transformer loss predictor
fn train_transformer(samples: &[LossSample], output_dir: &Path, epochs: usize) -> Result<()> {
    info!("Training Transformer Loss Predictor ({} epochs)...", epochs);

    // d_model=64, n_heads=4, seq_len=20
    let mut trainer = TransformerTrainer::new(64, 4, 20)
        .map_err(|e| anyhow::anyhow!("Failed to create Transformer trainer: {}", e))?;

    trainer
        .init_optimizer()
        .map_err(|e| anyhow::anyhow!("Failed to init optimizer: {}", e))?;

    // Label the samples if not already labeled
    let mut labeled_samples = samples.to_vec();
    for i in 0..labeled_samples.len() {
        if labeled_samples[i].future_loss == 0.0 && i + 10 < labeled_samples.len() {
            // Look ahead 100ms (~10 samples at 10ms intervals)
            let future_loss = labeled_samples[i..i + 10]
                .iter()
                .map(|s| s.loss_rate)
                .fold(0.0f32, |a, b| a.max(b));
            labeled_samples[i].future_loss = future_loss;
        }
    }

    let mut total_loss = 0.0f32;
    let mut loss_count = 0;

    for epoch in 0..epochs {
        let loss = trainer
            .train_batch(&labeled_samples)
            .map_err(|e| anyhow::anyhow!("Transformer training failed: {}", e))?;

        if loss > 0.0 {
            total_loss += loss;
            loss_count += 1;
        }

        if (epoch + 1) % 10 == 0 {
            let avg_loss = if loss_count > 0 {
                total_loss / loss_count as f32
            } else {
                0.0
            };
            info!("  Epoch {}/{}: loss = {:.6}", epoch + 1, epochs, avg_loss);
        }
    }

    // Save model
    let model_path = output_dir.join("transformer_loss.safetensors");
    trainer
        .save(&model_path)
        .map_err(|e| anyhow::anyhow!("Failed to save Transformer model: {}", e))?;

    let stats = trainer.stats();
    info!(
        "Transformer training complete: {} epochs, final loss = {:.6}",
        stats.epochs_trained, stats.training_loss
    );

    Ok(())
}

/// Train PPO congestion controller
fn train_ppo(experiences: &[DrlExperience], output_dir: &Path, steps: usize) -> Result<()> {
    info!("Training PPO Congestion Controller ({} steps)...", steps);

    // state_size=8, hidden_size=128
    let mut trainer = PpoTrainer::new(8, 128)
        .map_err(|e| anyhow::anyhow!("Failed to create PPO trainer: {}", e))?;

    trainer
        .init_optimizer()
        .map_err(|e| anyhow::anyhow!("Failed to init optimizer: {}", e))?;

    let mut total_loss = 0.0f32;
    let mut loss_count = 0;

    for step in 0..steps {
        let loss = trainer
            .train_batch(experiences)
            .map_err(|e| anyhow::anyhow!("PPO training failed: {}", e))?;

        if loss > 0.0 {
            total_loss += loss;
            loss_count += 1;
        }

        if (step + 1) % 100 == 0 {
            let avg_loss = if loss_count > 0 {
                total_loss / loss_count as f32
            } else {
                0.0
            };
            info!("  Step {}/{}: loss = {:.6}", step + 1, steps, avg_loss);
        }
    }

    // Save model
    let model_path = output_dir.join("ppo_congestion.safetensors");
    trainer
        .save(&model_path)
        .map_err(|e| anyhow::anyhow!("Failed to save PPO model: {}", e))?;

    let stats = trainer.stats();
    info!(
        "PPO training complete: {} steps, final loss = {:.6}",
        stats.steps_trained, stats.training_loss
    );

    Ok(())
}

/// Update config.json with training statistics
fn update_config(output_dir: &Path, data: &TrainingData) -> Result<()> {
    let config_path = output_dir.join("config.json");

    let config = serde_json::json!({
        "version": "0.2.0",
        "models": {
            "tier1": {
                "transformer_loss_predictor": {
                    "description": "Transformer-based packet loss prediction (50-100ms ahead)",
                    "file": "transformer_loss.safetensors",
                    "d_model": 64,
                    "n_heads": 4,
                    "sequence_length": 20,
                    "trained_samples": data.loss_samples.len()
                },
                "ppo_congestion_controller": {
                    "description": "PPO-based continuous congestion window optimization",
                    "file": "ppo_congestion.safetensors",
                    "state_size": 8,
                    "hidden_size": 128,
                    "trained_steps": data.drl_experiences.len()
                }
            }
        },
        "training_data": {
            "loss_samples": "loss_samples.json",
            "drl_experiences": "drl_experiences.json",
            "compression_samples": "compression_samples.json",
            "path_selection_samples": "path_selection_samples.json"
        },
        "metadata": {
            "last_updated": chrono_now(),
            "total_samples": data.loss_samples.len() + data.drl_experiences.len() +
                            data.compression_samples.len() + data.path_samples.len(),
            "contributing_servers": 1
        }
    });

    let json = serde_json::to_string_pretty(&config)?;
    fs::write(&config_path, json)?;

    info!("Updated config.json");
    Ok(())
}

/// Get current date in YYYY-MM-DD format
fn chrono_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    // Approximate date calculation (not accounting for leap years perfectly)
    let years = 1970 + days / 365;
    let day_of_year = days % 365;
    let month = day_of_year / 30 + 1;
    let day = day_of_year % 30 + 1;
    format!("{}-{:02}-{:02}", years, month.min(12), day.min(28))
}
