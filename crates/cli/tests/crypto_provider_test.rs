//! Regression test for issue #146: the workspace's dependency tree pulls in
//! both the `ring` and `aws-lc-rs` rustls crypto providers (via sqlx/reqwest
//! and quinn respectively), so rustls can't auto-select a default. Building a
//! `rustls::ServerConfig` — as the DoT/DoH and Web UI HTTPS listeners do —
//! used to panic on the first TLS operation in a fresh process unless a
//! provider was installed explicitly first.

use ferrous_dns_application::ports::TlsCertificatePort;
use ferrous_dns_infrastructure::tls::TlsCertificateService;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[tokio::test]
async fn server_config_builds_after_installing_crypto_provider() {
    ferrous_dns::install_crypto_provider();

    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");

    TlsCertificateService
        .generate_self_signed(cert_path.to_str().unwrap(), key_path.to_str().unwrap())
        .await
        .unwrap();

    let cert_chain = CertificateDer::pem_file_iter(&cert_path)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_file(&key_path).unwrap();

    let result = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key);

    assert!(result.is_ok());
}
