use anyhow::{Context, Result};
use rustls::Certificate;
use rustls::PrivateKey;
use std::fs;
use std::path::Path;

pub enum TlsConfig {
    SelfSigned,
    FromFiles { cert_path: String, key_path: String },
}

pub fn load_tls_config(config: TlsConfig) -> Result<(Vec<Certificate>, PrivateKey)> {
    match config {
        TlsConfig::SelfSigned => generate_self_signed_cert(),
        TlsConfig::FromFiles {
            cert_path,
            key_path,
        } => load_from_files(&cert_path, &key_path),
    }
}

fn generate_self_signed_cert() -> Result<(Vec<Certificate>, PrivateKey)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("Failed to generate self-signed certificate")?;

    let key = PrivateKey(cert.serialize_private_key_der());
    let cert_der = Certificate(cert.serialize_der()?);

    Ok((vec![cert_der], key))
}

fn load_from_files(cert_path: &str, key_path: &str) -> Result<(Vec<Certificate>, PrivateKey)> {
    let cert_file = fs::File::open(cert_path)
        .context(format!("Failed to open certificate file: {}", cert_path))?;
    let mut cert_reader = std::io::BufReader::new(cert_file);

    let certs = rustls_pemfile::certs(&mut cert_reader)
        .context("Failed to parse certificate PEM")?
        .into_iter()
        .map(Certificate)
        .collect();

    let key_file = fs::File::open(key_path)
        .context(format!("Failed to open private key file: {}", key_path))?;
    let mut key_reader = std::io::BufReader::new(key_file);

    let keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)
        .context("Failed to parse private key PEM")?;

    if keys.is_empty() {
        anyhow::bail!("No private key found in {}", key_path);
    }

    let key = PrivateKey(keys[0].clone());

    Ok((certs, key))
}

pub fn validate_cert_paths(cert_path: &str, key_path: &str) -> Result<()> {
    if !Path::new(cert_path).exists() {
        anyhow::bail!("Certificate file does not exist: {}", cert_path);
    }
    if !Path::new(key_path).exists() {
        anyhow::bail!("Private key file does not exist: {}", key_path);
    }
    Ok(())
}
