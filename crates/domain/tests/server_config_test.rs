use ferrous_dns_domain::ServerConfig;

fn config_with_bind(bind_address: &str) -> ServerConfig {
    ServerConfig {
        bind_address: bind_address.to_string(),
        ..ServerConfig::default()
    }
}

#[test]
fn listen_addresses_use_the_global_bind_address_by_default() {
    let config = config_with_bind("0.0.0.0");
    assert_eq!(config.dns_listen_address(), "0.0.0.0:53");
    assert_eq!(config.web_listen_address(), "0.0.0.0:8080");
    assert_eq!(config.dot_listen_address(), "0.0.0.0:853");
    assert_eq!(config.doq_listen_address(), "0.0.0.0:853");
}

#[test]
fn a_bare_ipv6_bind_address_is_bracketed() {
    let config = config_with_bind("::");
    assert_eq!(config.dns_listen_address(), "[::]:53");
    assert_eq!(config.dot_listen_address(), "[::]:853");
    assert_eq!(config.doq_listen_address(), "[::]:853");
    assert_eq!(config.web_listen_address(), "[::]:8080");
}

#[test]
fn an_already_bracketed_ipv6_bind_address_is_left_alone() {
    let config = config_with_bind("[::1]");
    assert_eq!(config.dns_listen_address(), "[::1]:53");
}

#[test]
fn every_listen_address_parses_as_a_socket_address() {
    let config = config_with_bind("::");
    for address in [
        config.dns_listen_address(),
        config.web_listen_address(),
        config.dot_listen_address(),
        config.doq_listen_address(),
    ] {
        address
            .parse::<std::net::SocketAddr>()
            .unwrap_or_else(|e| panic!("{address} should parse as a socket address: {e}"));
    }
}

#[test]
fn per_protocol_bind_addresses_override_the_global_one() {
    let mut config = config_with_bind("0.0.0.0");
    config.encrypted_dns.dot_bind_address = Some("[::]".to_string());
    config.encrypted_dns.doq_bind_address = Some("192.168.1.10".to_string());

    assert_eq!(config.dot_listen_address(), "[::]:853");
    assert_eq!(config.doq_listen_address(), "192.168.1.10:853");
    // Untouched protocols keep inheriting the global bind address.
    assert_eq!(config.dns_listen_address(), "0.0.0.0:53");
}

#[test]
fn doh_has_no_listen_address_when_it_is_co_hosted_on_the_web_port() {
    let config = config_with_bind("0.0.0.0");
    assert!(config.encrypted_dns.doh_port.is_none());
    assert_eq!(config.doh_listen_address(), None);
}

#[test]
fn doh_listen_address_honours_its_own_bind_address() {
    let mut config = config_with_bind("0.0.0.0");
    config.encrypted_dns.doh_port = Some(443);
    assert_eq!(config.doh_listen_address().as_deref(), Some("0.0.0.0:443"));

    config.encrypted_dns.doh_bind_address = Some("::".to_string());
    assert_eq!(config.doh_listen_address().as_deref(), Some("[::]:443"));
}
