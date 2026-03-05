use anyhow::Context;
use rustls::pki_types::CertificateDer;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use tracing::warn;

/// Loads a `rustls::ServerConfig` from PEM certificate and key files.
///
/// Returns `Ok(None)` if either file is absent — the caller should skip the
/// encrypted listener and continue with plain DNS. Returns `Err` only when a
/// file exists but cannot be parsed or contains an invalid key.
pub fn load_server_tls_config(
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<Option<Arc<rustls::ServerConfig>>> {
    if !Path::new(cert_path).exists() {
        warn!(
            path = cert_path,
            "TLS cert file not found — DoT/DoH disabled"
        );
        return Ok(None);
    }
    if !Path::new(key_path).exists() {
        warn!(path = key_path, "TLS key file not found — DoT/DoH disabled");
        return Ok(None);
    }

    let cert_file =
        File::open(cert_path).with_context(|| format!("Failed to open TLS cert: {cert_path}"))?;
    let key_file =
        File::open(key_path).with_context(|| format!("Failed to open TLS key: {key_path}"))?;

    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut BufReader::new(cert_file))
        .collect::<Result<_, _>>()
        .with_context(|| format!("Failed to parse TLS cert: {cert_path}"))?;

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_file))
        .with_context(|| format!("Failed to read TLS key: {key_path}"))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {key_path}"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("Failed to build rustls ServerConfig")?;

    Ok(Some(Arc::new(config)))
}
