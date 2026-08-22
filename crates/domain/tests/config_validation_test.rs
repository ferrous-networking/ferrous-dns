use ferrous_dns_domain::{Config, ConfigError};

/// A config that passes every check unrelated to bind addresses, so a failure
/// can only come from the address validation under test.
fn valid_config() -> Config {
    let mut config = Config::default();
    config.dns.upstream_servers = vec!["1.1.1.1:53".to_string()];
    config
}

fn validation_message(config: &Config) -> String {
    match config.validate() {
        Err(ConfigError::Validation(message)) => message,
        other => panic!("expected a validation error, got {other:?}"),
    }
}

#[test]
fn a_valid_config_passes() {
    valid_config().validate().unwrap();
}

#[test]
fn a_bare_ipv6_bind_address_is_accepted() {
    let mut config = valid_config();
    config.server.bind_address = "::".to_string();
    config.validate().unwrap();
}

#[test]
fn an_unparseable_bind_address_is_rejected() {
    let mut config = valid_config();
    config.server.bind_address = "192.168.1.300".to_string();

    let message = validation_message(&config);
    assert!(
        message.contains("server.bind_address"),
        "the message should name the offending key: {message}"
    );
}

#[test]
fn a_hostname_bind_address_is_rejected_rather_than_panicking_at_bind_time() {
    let mut config = valid_config();
    config.server.bind_address = "localhost".to_string();

    assert!(validation_message(&config).contains("not a hostname"));
}

#[test]
fn an_unparseable_per_protocol_bind_address_names_its_own_key() {
    let mut config = valid_config();
    config.server.encrypted_dns.dot_enabled = true;
    config.server.encrypted_dns.dot_bind_address = Some("not-an-address".to_string());

    let message = validation_message(&config);
    assert!(
        message.contains("dot_bind_address"),
        "the message should name the DoT key, not the global one: {message}"
    );
}

#[test]
fn a_bad_bind_address_on_a_disabled_listener_does_not_block_startup() {
    // The listener is never bound, so a stale value must not be fatal.
    let mut config = valid_config();
    config.server.encrypted_dns.doq_enabled = false;
    config.server.encrypted_dns.doq_bind_address = Some("not-an-address".to_string());

    config.validate().unwrap();
}

#[test]
fn the_doh_bind_address_is_only_checked_when_a_dedicated_port_is_set() {
    let mut config = valid_config();
    config.server.encrypted_dns.doh_enabled = true;
    config.server.encrypted_dns.doh_bind_address = Some("not-an-address".to_string());

    // No `doh_port`, so `/dns-query` is co-hosted and the address is unused.
    config.validate().unwrap();

    config.server.encrypted_dns.doh_port = Some(443);
    assert!(validation_message(&config).contains("doh_bind_address"));
}
