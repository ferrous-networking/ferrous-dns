use ferrous_dns_domain::EncryptedDnsConfig;

#[test]
fn defaults_disable_doq() {
    let config = EncryptedDnsConfig::default();
    assert!(!config.doq_enabled);
    assert_eq!(config.doq_port, 853);
}

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
fn bind_addresses_are_absent_unless_configured() {
    let config = EncryptedDnsConfig::default();
    assert!(config.dot_bind_address.is_none());
    assert!(config.doh_bind_address.is_none());
    assert!(config.doq_bind_address.is_none());
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
    assert_eq!(config.dot_bind_address.as_deref(), Some("[::]"));
    assert_eq!(config.doh_bind_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(config.doq_bind_address.as_deref(), Some("192.168.1.10"));
}

#[test]
fn round_trips_doq_fields() {
    let original = EncryptedDnsConfig {
        dot_enabled: true,
        dot_port: 853,
        dot_bind_address: Some("[::]".to_string()),
        doh_enabled: false,
        doh_port: None,
        doh_bind_address: None,
        doq_enabled: true,
        doq_port: 8853,
        doq_bind_address: None,
        tls_cert_path: "/data/cert.pem".to_string(),
        tls_key_path: "/data/key.pem".to_string(),
    };
    let toml_str = toml::to_string(&original).unwrap();
    let restored: EncryptedDnsConfig = toml::from_str(&toml_str).unwrap();
    assert_eq!(restored.doq_enabled, original.doq_enabled);
    assert_eq!(restored.doq_port, original.doq_port);
    assert_eq!(restored.dot_bind_address, original.dot_bind_address);
    assert_eq!(restored.doq_bind_address, original.doq_bind_address);
}
