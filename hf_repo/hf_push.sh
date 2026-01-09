#!/bin/bash
# Push Oxidize ML models and config to Hugging Face Hub
#
# Usage:
#   ./scripts/hf_push.sh              # Push model card + config only
#   ./scripts/hf_push.sh --models     # Also push trained models
#
# Requirements:
#   - hf CLI installed and logged in (pip install "huggingface_hub[cli]")
#   - HF_TOKEN environment variable (or logged in via `hf auth login`)

set -e

REPO="gagansuie/oxidize-models"
HF_REPO_DIR="hf_repo"
MODEL_DIR="/tmp/oxidize_models"

echo "🦀 Oxidize → Hugging Face Hub"
echo "Repository: https://huggingface.co/$REPO"
echo ""

# Check if logged in
if ! hf auth whoami &> /dev/null; then
    echo "❌ Not logged in to Hugging Face"
    echo "Run: hf auth login"
    exit 1
fi

# Create temp directory for upload
UPLOAD_DIR=$(mktemp -d)
trap "rm -rf $UPLOAD_DIR" EXIT

# Copy model card and config
cp "$HF_REPO_DIR/README.md" "$UPLOAD_DIR/"
cp "$HF_REPO_DIR/config.json" "$UPLOAD_DIR/"

echo "✓ Copied model card and config"

# Optionally copy trained models
if [[ "$1" == "--models" ]]; then
    if [[ -f "$MODEL_DIR/lstm_loss_predictor.safetensors" ]]; then
        cp "$MODEL_DIR/lstm_loss_predictor.safetensors" "$UPLOAD_DIR/"
        echo "✓ Copied LSTM model"
    else
        echo "⚠ LSTM model not found at $MODEL_DIR/lstm_loss_predictor.safetensors"
    fi
    
    if [[ -f "$MODEL_DIR/dqn_congestion.safetensors" ]]; then
        cp "$MODEL_DIR/dqn_congestion.safetensors" "$UPLOAD_DIR/"
        echo "✓ Copied DQN model"
    else
        echo "⚠ DQN model not found at $MODEL_DIR/dqn_congestion.safetensors"
    fi
fi

# Upload to HF Hub
echo ""
echo "Uploading to $REPO..."
hf upload "$REPO" "$UPLOAD_DIR" . --repo-type model

echo ""
echo "✅ Done! View at: https://huggingface.co/$REPO"
