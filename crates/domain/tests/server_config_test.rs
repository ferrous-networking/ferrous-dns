use ferrous_dns_domain::{BindAddress, ServerConfig};
use std::net::{IpAddr, SocketAddr};

fn server_toml(extra: &str) -> String {
    format!("dns_port = 53\nweb_port = 8080\nbind_address = \"0.0.0.0\"\n{extra}")
}

fn parse(toml_src: &str) -> ServerConfig {
    toml::from_str(toml_src).unwrap()
}

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

#[test]
fn listen_addresses_use_the_global_bind_address_by_default() {
    let config = parse(&server_toml(""));
    assert_eq!(config.dns_listen_address(), addr("0.0.0.0:53"));
    assert_eq!(config.web_listen_address(), addr("0.0.0.0:8080"));
    assert_eq!(config.dot_listen_address(), addr("0.0.0.0:853"));
    assert_eq!(config.doq_listen_address(), addr("0.0.0.0:853"));
}

#[test]
fn bare_and_bracketed_ipv6_bind_addresses_are_the_same_address() {
    for spelling in ["::", "[::]"] {
        let config = parse(&format!(
            "dns_port = 53\nweb_port = 8080\nbind_address = \"{spelling}\""
        ));
        assert_eq!(config.dns_listen_address(), addr("[::]:53"), "{spelling}");
        assert_eq!(config.web_listen_address(), addr("[::]:8080"), "{spelling}");
    }
}

#[test]
fn test_bind_address_auto_parses() {
    let config = parse("dns_port = 53\nweb_port = 8080\nbind_address = \"auto\"");
    assert_eq!(config.bind_address, BindAddress::Auto);
}

#[test]
fn test_missing_bind_address_defaults_to_auto() {
    let config = parse("dns_port = 53\nweb_port = 8080");
    assert_eq!(config.bind_address, BindAddress::Auto);
}

#[test]
fn test_default_server_config_binds_auto() {
    assert_eq!(ServerConfig::default().bind_address, BindAddress::Auto);
}

#[test]
fn test_auto_listens_on_the_unspecified_ipv6_address() {
    let config = parse(
        "dns_port = 53\nweb_port = 8080\nbind_address = \"auto\"\n[encrypted_dns]\ndoh_port = 443",
    );
    assert_eq!(config.dns_listen_address(), addr("[::]:53"));
    assert_eq!(config.web_listen_address(), addr("[::]:8080"));
    assert_eq!(config.dot_listen_address(), addr("[::]:853"));
    assert_eq!(config.doq_listen_address(), addr("[::]:853"));
    assert_eq!(config.doh_listen_address(), Some(addr("[::]:443")));
}

#[test]
fn test_explicit_ipv4_bind_address_is_not_upgraded() {
    let config = parse(&server_toml(""));
    assert_eq!(
        config.bind_address,
        BindAddress::Ip("0.0.0.0".parse().unwrap())
    );
    assert_eq!(config.dns_listen_address(), addr("0.0.0.0:53"));
}

#[test]
fn test_per_listener_override_wins_over_auto() {
    let config = parse(
        "dns_port = 53\nweb_port = 8080\nbind_address = \"auto\"\nweb_bind_address = \"127.0.0.1\"\n\
         [encrypted_dns]\ndot_bind_address = \"192.168.1.10\"",
    );
    assert_eq!(config.web_listen_address(), addr("127.0.0.1:8080"));
    assert_eq!(config.dot_listen_address(), addr("192.168.1.10:853"));
    assert_eq!(config.dns_listen_address(), addr("[::]:53"));
}

fn without_ipv6(mut config: ServerConfig) -> ServerConfig {
    config.bind_address = config.bind_address.without_ipv6();
    config
}

#[test]
fn test_auto_without_ipv6_listens_on_the_unspecified_ipv4_address() {
    let config = without_ipv6(parse(
        "dns_port = 53\nweb_port = 8080\nbind_address = \"auto\"\n[encrypted_dns]\ndoh_port = 443",
    ));
    assert_eq!(config.dns_listen_address(), addr("0.0.0.0:53"));
    assert_eq!(config.web_listen_address(), addr("0.0.0.0:8080"));
    assert_eq!(config.dot_listen_address(), addr("0.0.0.0:853"));
    assert_eq!(config.doq_listen_address(), addr("0.0.0.0:853"));
    assert_eq!(config.doh_listen_address(), Some(addr("0.0.0.0:443")));
}

#[test]
fn test_explicit_bind_address_is_kept_without_ipv6() {
    for (spelling, dns) in [
        ("[::]", "[::]:53"),
        ("0.0.0.0", "0.0.0.0:53"),
        ("192.168.1.10", "192.168.1.10:53"),
    ] {
        let config = without_ipv6(parse(&format!(
            "dns_port = 53\nweb_port = 8080\nbind_address = \"{spelling}\""
        )));
        assert_eq!(config.dns_listen_address(), addr(dns), "{spelling}");
    }
}

#[test]
fn test_per_listener_override_is_kept_without_ipv6() {
    let config = without_ipv6(parse(
        "dns_port = 53\nweb_port = 8080\nbind_address = \"auto\"\nweb_bind_address = \"::1\"\n\
         [encrypted_dns]\ndot_bind_address = \"[::]\"",
    ));
    assert_eq!(config.web_listen_address(), addr("[::1]:8080"));
    assert_eq!(config.dot_listen_address(), addr("[::]:853"));
    assert_eq!(config.dns_listen_address(), addr("0.0.0.0:53"));
}

#[test]
fn test_web_bind_address_rejects_auto() {
    let err = toml::from_str::<ServerConfig>(&server_toml("web_bind_address = \"auto\""))
        .unwrap_err()
        .to_string();
    assert!(err.contains("web_bind_address"), "names the key: {err}");
}

#[test]
fn test_bind_address_displays_auto() {
    assert_eq!(BindAddress::Auto.to_string(), "auto");
    assert_eq!("[::]".parse::<BindAddress>().unwrap().to_string(), "::");
    assert_eq!(
        "0.0.0.0".parse::<BindAddress>().unwrap().to_string(),
        "0.0.0.0"
    );
}

#[test]
fn test_bind_address_hostname_error_mentions_auto() {
    let err = "localhost".parse::<BindAddress>().unwrap_err();
    assert!(err.contains("\"auto\""), "{err}");
    assert!(err.contains("not a hostname"), "{err}");
}

#[test]
fn a_hostname_bind_address_is_rejected_at_parse_time() {
    let err = toml::from_str::<ServerConfig>(
        "dns_port = 53\nweb_port = 8080\nbind_address = \"localhost\"",
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("bind_address"), "names the key: {err}");
    assert!(err.contains("not a hostname"), "{err}");
}

#[test]
fn a_bracketed_ipv4_bind_address_is_rejected() {
    assert!(toml::from_str::<ServerConfig>(
        "dns_port = 53\nweb_port = 8080\nbind_address = \"[127.0.0.1]\"",
    )
    .is_err());
}

#[test]
fn per_protocol_bind_addresses_override_the_global_one() {
    let config = parse(&server_toml(
        "[encrypted_dns]\ndot_bind_address = \"[::]\"\ndoq_bind_address = \"192.168.1.10\"",
    ));

    assert_eq!(config.dot_listen_address(), addr("[::]:853"));
    assert_eq!(config.doq_listen_address(), addr("192.168.1.10:853"));
    // Untouched protocols keep inheriting the global bind address.
    assert_eq!(config.dns_listen_address(), addr("0.0.0.0:53"));
}

#[test]
fn an_invalid_per_protocol_bind_address_names_its_own_key() {
    let err = toml::from_str::<ServerConfig>(&server_toml(
        "[encrypted_dns]\ndoq_bind_address = \"not-an-address\"",
    ))
    .unwrap_err()
    .to_string();
    assert!(err.contains("doq_bind_address"), "{err}");
}

#[test]
fn web_bind_address_moves_only_the_web_listener() {
    let config = parse(&server_toml("web_bind_address = \"127.0.0.1\""));

    assert_eq!(config.web_listen_address(), addr("127.0.0.1:8080"));
    assert_eq!(config.dns_listen_address(), addr("0.0.0.0:53"));
    assert_eq!(config.dot_listen_address(), addr("0.0.0.0:853"));
}

#[test]
fn web_bind_address_accepts_bare_and_bracketed_ipv6() {
    for spelling in ["::1", "[::1]"] {
        let config = parse(&server_toml(&format!("web_bind_address = \"{spelling}\"")));
        assert_eq!(
            config.web_listen_address(),
            addr("[::1]:8080"),
            "{spelling}"
        );
    }
}

#[test]
fn a_hostname_web_bind_address_is_rejected_and_names_its_key() {
    let err = toml::from_str::<ServerConfig>(&server_toml("web_bind_address = \"localhost\""))
        .unwrap_err()
        .to_string();
    assert!(err.contains("web_bind_address"), "names the key: {err}");
    assert!(err.contains("not a hostname"), "{err}");
}

#[test]
fn doh_has_no_listen_address_when_it_is_co_hosted_on_the_web_port() {
    let config = parse(&server_toml(""));
    assert!(config.encrypted_dns.doh_port.is_none());
    assert_eq!(config.doh_listen_address(), None);
}

#[test]
fn doh_listen_address_honours_its_own_bind_address() {
    let config = parse(&server_toml("[encrypted_dns]\ndoh_port = 443"));
    assert_eq!(config.doh_listen_address(), Some(addr("0.0.0.0:443")));

    let config = parse(&server_toml(
        "[encrypted_dns]\ndoh_port = 443\ndoh_bind_address = \"::\"",
    ));
    assert_eq!(config.doh_listen_address(), Some(addr("[::]:443")));
}

#[test]
fn trusted_proxies_default_to_loopback_only() {
    let config = parse(&server_toml(""));
    let trusts = |ip: &str| {
        let ip: IpAddr = ip.parse().unwrap();
        config.trusted_proxies.iter().any(|net| net.contains(ip))
    };
    assert!(trusts("127.0.0.1"));
    assert!(trusts("127.8.9.10"));
    assert!(trusts("::1"));
    assert!(!trusts("192.168.1.1"));
    assert!(!trusts("::2"));
}

#[test]
fn trusted_proxies_accept_cidrs_and_bare_addresses() {
    let config = parse(&server_toml(
        "trusted_proxies = [\"10.0.0.0/8\", \"fd00::/8\", \"192.168.1.2\"]",
    ));
    let trusts = |ip: &str| {
        let ip: IpAddr = ip.parse().unwrap();
        config.trusted_proxies.iter().any(|net| net.contains(ip))
    };
    assert!(trusts("10.1.2.3"));
    assert!(trusts("fd12::1"));
    assert!(trusts("192.168.1.2"));
    assert!(!trusts("192.168.1.3"));
    assert!(
        !trusts("127.0.0.1"),
        "an explicit list replaces the default"
    );
}

#[test]
fn an_invalid_trusted_proxy_is_rejected() {
    assert!(
        toml::from_str::<ServerConfig>(&server_toml("trusted_proxies = [\"10.0.0.0/33\"]"))
            .is_err()
    );
}
