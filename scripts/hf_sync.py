#!/usr/bin/env python3
"""Hugging Face Hub sync utilities for ML training pipeline."""
import os
import sys
from pathlib import Path


def login():
    """Login to Hugging Face Hub."""
    from huggingface_hub import login as hf_login
    
    token = os.environ.get("HF_TOKEN")
    if not token:
        print("❌ HF_TOKEN environment variable not set")
        sys.exit(1)
    
    hf_login(token=token)
    print("✅ Logged in to Hugging Face")


def download():
    """Download training data from HF Hub."""
    from huggingface_hub import snapshot_download
    
    repo = os.environ.get("HF_REPO", "gagansuie/oxidize-models")
    local_dir = "./hf_download"
    
    try:
        snapshot_download(
            repo_id=repo,
            allow_patterns="training_data/*.json",
            local_dir=local_dir
        )
        print(f"✅ Downloaded training data from {repo}")
    except Exception as e:
        print(f"⚠️ Could not download training data: {e}")
        print("   (This is normal for a new repo with no data yet)")


def upload():
    """Upload models and data to HF Hub."""
    from huggingface_hub import HfApi
    
    repo = os.environ.get("HF_REPO", "gagansuie/oxidize-models")
    folder_path = "./hf_repo"
    
    if not Path(folder_path).exists():
        print(f"❌ Folder {folder_path} does not exist")
        sys.exit(1)
    
    # Check if folder has any files
    files = list(Path(folder_path).rglob("*"))
    if not any(f.is_file() for f in files):
        print(f"⚠️ No files to upload in {folder_path}")
        return
    
    api = HfApi()
    api.upload_folder(
        folder_path=folder_path,
        repo_id=repo,
        repo_type="model"
    )
    print(f"✅ Uploaded to {repo}")


def aggregate():
    """Aggregate training data from multiple JSON files."""
    import json
    import glob
    
    training_dir = "training_data"
    loss_samples = []
    drl_experiences = []
    
    # Aggregate loss samples
    patterns = [f"{training_dir}/*loss*.json", f"{training_dir}/training-*.json"]
    for pattern in patterns:
        for f in glob.glob(pattern):
            try:
                with open(f) as fp:
                    data = json.load(fp)
                if isinstance(data, list):
                    loss_samples.extend(data)
                elif isinstance(data, dict) and "loss_samples" in data:
                    loss_samples.extend(data["loss_samples"])
            except Exception as e:
                print(f"Warning: Could not parse {f}: {e}")
    
    # Aggregate DRL experiences
    patterns = [
        f"{training_dir}/*drl*.json",
        f"{training_dir}/*experience*.json",
        f"{training_dir}/training-*.json"
    ]
    for pattern in patterns:
        for f in glob.glob(pattern):
            try:
                with open(f) as fp:
                    data = json.load(fp)
                if isinstance(data, list) and len(data) > 0 and "state" in str(data[0]):
                    drl_experiences.extend(data)
                elif isinstance(data, dict) and "drl_experiences" in data:
                    drl_experiences.extend(data["drl_experiences"])
            except Exception as e:
                print(f"Warning: Could not parse {f}: {e}")
    
    print(f"📊 Aggregated {len(loss_samples)} loss samples, {len(drl_experiences)} DRL experiences")
    
    # Save aggregated data
    if loss_samples:
        with open(f"{training_dir}/loss_samples.json", "w") as fp:
            json.dump(loss_samples, fp)
        print(f"   Saved {training_dir}/loss_samples.json")
    
    if drl_experiences:
        with open(f"{training_dir}/drl_experiences.json", "w") as fp:
            json.dump(drl_experiences, fp)
        print(f"   Saved {training_dir}/drl_experiences.json")


def main():
    if len(sys.argv) < 2:
        print("Usage: hf_sync.py [login|download|upload|aggregate]")
        sys.exit(1)
    
    cmd = sys.argv[1]
    
    commands = {
        "login": login,
        "download": download,
        "upload": upload,
        "aggregate": aggregate,
    }
    
    if cmd not in commands:
        print(f"Unknown command: {cmd}")
        print(f"Available: {', '.join(commands.keys())}")
        sys.exit(1)
    
    commands[cmd]()


if __name__ == "__main__":
    main()
