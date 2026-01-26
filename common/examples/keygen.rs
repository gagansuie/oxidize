//! Authentication Key Generator
//!
//! Generates Ed25519 keypair for app signing and API credentials.
//!
//! Usage:
//!   cargo run --package oxidize-common --example keygen

use oxidize_common::auth::{generate_api_credentials, generate_app_keypair};

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
