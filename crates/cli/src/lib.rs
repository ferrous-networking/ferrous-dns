//! Minimal library surface for the `ferrous-dns` binary.
//!
//! Exists so integration tests under `tests/` can exercise startup-critical
//! code paths (like crypto provider installation) that would otherwise be
//! private to `main.rs`.

/// Installs the process-wide rustls crypto provider.
///
/// The dependency tree pulls in both the `ring` and `aws-lc-rs` crypto
/// providers (via sqlx/reqwest and quinn respectively), so rustls can't pick
/// a default on its own. This must run before any TLS config (DoT, DoH, or
/// the Web UI's HTTPS listener) is built, or the first
/// `rustls::ServerConfig`/`ClientConfig` builder call panics.
pub fn install_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}
