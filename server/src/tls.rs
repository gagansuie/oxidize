use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs;
use std::path::Path;

pub enum TlsConfig {
    SelfSigned,
    FromFiles { cert_path: String, key_path: String },
}

pub fn load_tls_config(
    config: TlsConfig,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    match config {
        TlsConfig::SelfSigned => generate_self_signed_cert(),
        TlsConfig::FromFiles {
            cert_path,
            key_path,
        } => load_from_files(&cert_path, &key_path),
    }
}

fn generate_self_signed_cert() -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .context("Failed to generate self-signed certificate")?;

    let key = PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into());
    let cert_der = CertificateDer::from(cert.cert.der().to_vec());

    Ok((vec![cert_der], key))
}

fn load_from_files(
    cert_path: &str,
    key_path: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let cert_file = fs::File::open(cert_path)
        .context(format!("Failed to open certificate file: {}", cert_path))?;
    let mut cert_reader = std::io::BufReader::new(cert_file);

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to parse certificate PEM")?;

    let key_file = fs::File::open(key_path)
        .context(format!("Failed to open private key file: {}", key_path))?;
    let mut key_reader = std::io::BufReader::new(key_file);

    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("Failed to parse private key PEM")?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;

    Ok((certs, key))
}

#[allow(dead_code)]
pub fn validate_cert_paths(cert_path: &str, key_path: &str) -> Result<()> {
    if !Path::new(cert_path).exists() {
        anyhow::bail!("Certificate file does not exist: {}", cert_path);
    }
    if !Path::new(key_path).exists() {
        anyhow::bail!("Private key file does not exist: {}", key_path);
    }
    Ok(())
}
