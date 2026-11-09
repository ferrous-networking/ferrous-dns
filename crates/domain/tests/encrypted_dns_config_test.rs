use ferrous_dns_domain::EncryptedDnsConfig;

#[test]
fn parses_doq_fields_from_toml() {
    let toml = r#"
        dot_enabled   = true
        dot_port      = 853
        doh_enabled   = true
        doh_port      = 8053
        doq_enabled   = true
        doq_port      = 8853
        tls_cert_path = "/data/cert.pem"
        tls_key_path  = "/data/key.pem"
    "#;
    let config: EncryptedDnsConfig = toml::from_str(toml).unwrap();
    assert!(config.doq_enabled);
    assert_eq!(config.doq_port, 8853);
}

#[test]
fn parses_per_protocol_bind_addresses_from_toml() {
    let toml = r#"
        dot_enabled      = true
        dot_bind_address = "[::]"
        doh_enabled      = true
        doh_port         = 8053
        doh_bind_address = "127.0.0.1"
        doq_enabled      = true
        doq_bind_address = "192.168.1.10"
    "#;
    let config: EncryptedDnsConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.dot_bind_address, "::".parse().ok());
    assert_eq!(config.doh_bind_address, "127.0.0.1".parse().ok());
    assert_eq!(config.doq_bind_address, "192.168.1.10".parse().ok());
    assert!(!config.doh_allow_unregistered_ids);
}

#[test]
fn parses_doh_allow_unregistered_ids_from_toml() {
    let toml = r#"
        doh_enabled                = true
        doh_allow_unregistered_ids = true
    "#;
    let config: EncryptedDnsConfig = toml::from_str(toml).unwrap();
    assert!(config.doh_enabled);
    assert!(config.doh_allow_unregistered_ids);
}
