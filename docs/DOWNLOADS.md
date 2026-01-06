# Download Oxidize Client

Get the latest client for your operating system.

## Latest Release

Download from [GitHub Releases](https://github.com/YOUR_USERNAME/oxidize/releases/latest)

## Quick Install

### Linux (x86_64)
```bash
# Download
wget https://github.com/YOUR_USERNAME/oxidize/releases/latest/download/oxidize-v0.1.0-x86_64-unknown-linux-gnu.tar.gz

# Extract
tar xzf oxidize-v0.1.0-x86_64-unknown-linux-gnu.tar.gz

# Move to PATH
sudo mv oxidize-client /usr/local/bin/

# Verify
oxidize-client --help
```

### Linux (ARM64)
```bash
# Download
wget https://github.com/YOUR_USERNAME/oxidize/releases/latest/download/oxidize-v0.1.0-aarch64-unknown-linux-gnu.tar.gz

# Extract
tar xzf oxidize-v0.1.0-aarch64-unknown-linux-gnu.tar.gz

# Move to PATH
sudo mv oxidize-client /usr/local/bin/

# Verify
oxidize-client --help
```

### macOS (Intel)
```bash
# Download
curl -L -o oxidize.tar.gz https://github.com/YOUR_USERNAME/oxidize/releases/latest/download/oxidize-v0.1.0-x86_64-apple-darwin.tar.gz

# Extract
tar xzf oxidize.tar.gz

# Move to PATH
sudo mv oxidize-client /usr/local/bin/

# Verify
oxidize-client --help
```

### macOS (Apple Silicon)
```bash
# Download
curl -L -o oxidize.tar.gz https://github.com/YOUR_USERNAME/oxidize/releases/latest/download/oxidize-v0.1.0-aarch64-apple-darwin.tar.gz

# Extract
tar xzf oxidize.tar.gz

# Move to PATH
sudo mv oxidize-client /usr/local/bin/

# Verify
oxidize-client --help
```

### Windows
1. Download [oxidize-v0.1.0-x86_64-pc-windows-msvc.zip](https://github.com/YOUR_USERNAME/oxidize/releases/latest/download/oxidize-v0.1.0-x86_64-pc-windows-msvc.zip)
2. Extract the ZIP file
3. Run `oxidize-client.exe` from Command Prompt or PowerShell

## Quick Start

### Test Your Connection First
```bash
# Run a speed test to see your improvement
oxidize-client --server relay.yourdomain.com:4433 --speedtest

# Get JSON output for scripting
oxidize-client --server relay.yourdomain.com:4433 --speedtest --json
```

### Connect to Public Relay
```bash
# Basic connection
oxidize-client --server relay.yourdomain.com:4433 --no-tun

# With TUN interface (requires sudo/admin)
sudo oxidize-client --server relay.yourdomain.com:4433
```

### Create Config File

Create `config.toml`:
```toml
enable_compression = true
enable_dns_prefetch = true
tun_mtu = 1500
```

Use it:
```bash
oxidize-client --server relay.yourdomain.com:4433 --config config.toml
```

## Build from Source

### Prerequisites
- Rust 1.75+
- Git

### Steps
```bash
# Clone
git clone https://github.com/YOUR_USERNAME/oxidize.git
cd oxidize

# Build
cargo build --release

# Binaries in target/release/
./target/release/oxidize-client --help
./target/release/oxidize-server --help
```

## Platform Support

| Platform | Architecture | Status |
|----------|-------------|--------|
| Linux | x86_64 | ✅ Supported |
| Linux | ARM64 | ✅ Supported |
| macOS | Intel | ✅ Supported |
| macOS | Apple Silicon | ✅ Supported |
| Windows | x86_64 | ✅ Supported |

## Verify Downloads

All releases are signed and include SHA256 checksums.

```bash
# Download checksum file
wget https://github.com/YOUR_USERNAME/oxidize/releases/latest/download/SHA256SUMS

# Verify
sha256sum -c SHA256SUMS
```

## Auto-Update Script

```bash
#!/bin/bash
# update-oxidize.sh

REPO="YOUR_USERNAME/oxidize"
LATEST=$(curl -s https://api.github.com/repos/$REPO/releases/latest | grep -Po '"tag_name": "\K.*?(?=")')
PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

if [[ "$ARCH" == "x86_64" ]]; then
    TARGET="x86_64-unknown-${PLATFORM}-gnu"
elif [[ "$ARCH" == "aarch64" ]] || [[ "$ARCH" == "arm64" ]]; then
    TARGET="aarch64-unknown-${PLATFORM}-gnu"
fi

URL="https://github.com/$REPO/releases/download/$LATEST/oxidize-$LATEST-$TARGET.tar.gz"

echo "Downloading Oxidize $LATEST for $TARGET..."
wget -O /tmp/oxidize.tar.gz $URL
tar xzf /tmp/oxidize.tar.gz -C /tmp
sudo mv /tmp/oxidize-client /usr/local/bin/
rm /tmp/oxidize.tar.gz

echo "✅ Updated to $LATEST"
oxidize-client --version
```

## Package Managers (Coming Soon)

We're working on:
- Homebrew (macOS/Linux)
- Chocolatey (Windows)
- APT/Yum repositories

## Getting Help

- 📖 [Documentation](https://github.com/YOUR_USERNAME/oxidize)
- 🐛 [Report Issues](https://github.com/YOUR_USERNAME/oxidize/issues)
- 💬 [Discussions](https://github.com/YOUR_USERNAME/oxidize/discussions)

## Security

Found a vulnerability? Email: security@yourdomain.com
