#!/bin/bash
# Oxidize Authentication Key Generator
# Generates Ed25519 keypair for app signing and API credentials
#
# Usage:
#   ./scripts/generate-auth-keys.sh
#
# Output:
#   - auth-keys/app_private_key.hex  (KEEP SECRET - embed in app binary)
#   - auth-keys/app_public_key.hex   (Safe to publish - add to server config)
#   - auth-keys/api_secret.hex       (KEEP SECRET - server-side only)
#   - auth-keys/sample_api_key.hex   (Sample user API key for testing)
#   - auth-keys/sample_api_secret.hex (Sample user API secret for testing)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OUTPUT_DIR="$PROJECT_ROOT/auth-keys"

echo "🔐 Oxidize Authentication Key Generator"
echo "========================================"
echo ""

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check if keys already exist
if [ -f "$OUTPUT_DIR/app_private_key.hex" ]; then
    echo "⚠️  Keys already exist in $OUTPUT_DIR"
    echo "   Delete the directory to regenerate."
    echo ""
    read -p "Overwrite existing keys? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted."
        exit 1
    fi
fi

# Generate keys using Rust
cd "$PROJECT_ROOT"

echo "📝 Generating Ed25519 keypair for app signing..."
echo "📝 Generating API secret..."
echo ""

# Create a temporary Rust program to generate keys
TEMP_RS=$(mktemp)
cat > "$TEMP_RS" << 'EOF'
use oxidize_common::auth::{generate_app_keypair, generate_api_credentials};

fn main() {
    // Generate app signing keypair
    let (app_private, app_public) = generate_app_keypair();
    println!("APP_PRIVATE={}", app_private);
    println!("APP_PUBLIC={}", app_public);
    
    // Generate server API secret
    let (_, api_secret) = generate_api_credentials();
    println!("API_SECRET={}", api_secret);
    
    // Generate sample user credentials (for testing)
    let (sample_key, sample_secret) = generate_api_credentials();
    println!("SAMPLE_API_KEY={}", sample_key);
    println!("SAMPLE_API_SECRET={}", sample_secret);
}
EOF

# Run cargo to generate keys
OUTPUT=$(cargo run --quiet --example keygen 2>/dev/null || {
    # If keygen example doesn't exist, create it
    mkdir -p "$PROJECT_ROOT/common/examples"
    mv "$TEMP_RS" "$PROJECT_ROOT/common/examples/keygen.rs"
    cargo run --quiet --package oxidize-common --example keygen
})

rm -f "$TEMP_RS"

# Parse output and save to files
echo "$OUTPUT" | while IFS='=' read -r key value; do
    case "$key" in
        APP_PRIVATE)
            echo "$value" > "$OUTPUT_DIR/app_private_key.hex"
            echo "✅ App private key: $OUTPUT_DIR/app_private_key.hex"
            ;;
        APP_PUBLIC)
            echo "$value" > "$OUTPUT_DIR/app_public_key.hex"
            echo "✅ App public key:  $OUTPUT_DIR/app_public_key.hex"
            ;;
        API_SECRET)
            echo "$value" > "$OUTPUT_DIR/api_secret.hex"
            echo "✅ API secret:      $OUTPUT_DIR/api_secret.hex"
            ;;
        SAMPLE_API_KEY)
            echo "$value" > "$OUTPUT_DIR/sample_api_key.hex"
            echo "✅ Sample API key:  $OUTPUT_DIR/sample_api_key.hex"
            ;;
        SAMPLE_API_SECRET)
            echo "$value" > "$OUTPUT_DIR/sample_api_secret.hex"
            echo "✅ Sample API secret: $OUTPUT_DIR/sample_api_secret.hex"
            ;;
    esac
done

# Set restrictive permissions
chmod 600 "$OUTPUT_DIR/app_private_key.hex"
chmod 600 "$OUTPUT_DIR/api_secret.hex"
chmod 600 "$OUTPUT_DIR/sample_api_secret.hex"
chmod 644 "$OUTPUT_DIR/app_public_key.hex"
chmod 644 "$OUTPUT_DIR/sample_api_key.hex"

echo ""
echo "========================================"
echo "🎉 Keys generated successfully!"
echo ""
echo "📋 Next steps:"
echo ""
echo "1. SERVER SETUP:"
echo "   Add to your server config (example-config-server.toml):"
echo "   enable_auth = true"
echo "   app_public_key = \"$(cat "$OUTPUT_DIR/app_public_key.hex")\""
echo "   api_secret = \"$(cat "$OUTPUT_DIR/api_secret.hex")\""
echo ""
echo "2. APP BUILD:"
echo "   The app private key must be embedded at compile time."
echo "   Set environment variable before building:"
echo "   export OXIDIZE_APP_SIGNING_KEY=$(cat "$OUTPUT_DIR/app_private_key.hex")"
echo ""
echo "3. USER API KEYS:"
echo "   Issue API keys to users from your backend."
echo "   For testing, use the sample credentials:"
echo "   API Key:    $(cat "$OUTPUT_DIR/sample_api_key.hex")"
echo "   API Secret: $(cat "$OUTPUT_DIR/sample_api_secret.hex")"
echo ""
echo "⚠️  SECURITY NOTES:"
echo "   - NEVER commit auth-keys/ to version control"
echo "   - Keep app_private_key.hex and api_secret.hex SECRET"
echo "   - The app_public_key.hex is safe to publish"
echo ""
