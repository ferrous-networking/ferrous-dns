use ferrous_dns::server::load_server_tls_config;

/// Generates a throwaway self-signed cert/key pair and writes them to temp
/// files, mirroring the pattern in `ferrous_dns_infrastructure::tls::generate_self_signed_cert`.
fn write_test_cert() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "localhost");
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();

    let cert_file = tempfile::NamedTempFile::new().unwrap();
    let key_file = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(cert_file.path(), cert.pem()).unwrap();
    std::fs::write(key_file.path(), key_pair.serialize_pem()).unwrap();
    (cert_file, key_file)
}

#[test]
fn sets_requested_alpn_protocols() {
    ferrous_dns::install_crypto_provider();
    let (cert_file, key_file) = write_test_cert();
    let config = load_server_tls_config(
        cert_file.path().to_str().unwrap(),
        key_file.path().to_str().unwrap(),
        "test",
        &[b"doq"],
    )
    .unwrap()
    .unwrap();
    assert_eq!(config.alpn_protocols, vec![b"doq".to_vec()]);
}

#[test]
fn empty_alpn_matches_current_dot_doh_behavior() {
    ferrous_dns::install_crypto_provider();
    let (cert_file, key_file) = write_test_cert();
    let config = load_server_tls_config(
        cert_file.path().to_str().unwrap(),
        key_file.path().to_str().unwrap(),
        "test",
        &[],
    )
    .unwrap()
    .unwrap();
    assert!(config.alpn_protocols.is_empty());
}

#[test]
fn missing_cert_returns_none_regardless_of_alpn() {
    let result = load_server_tls_config(
        "/nonexistent/cert.pem",
        "/nonexistent/key.pem",
        "test",
        &[b"doq"],
    )
    .unwrap();
    assert!(result.is_none());
}
