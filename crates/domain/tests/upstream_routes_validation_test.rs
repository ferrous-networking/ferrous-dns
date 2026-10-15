use ferrous_dns_domain::config::upstream::{normalize_route_domain, validate_pool_routes};
use ferrous_dns_domain::{Config, DomainError, UpstreamPool};

fn default_pool() -> UpstreamPool {
    UpstreamPool {
        name: "public".to_string(),
        servers: vec!["udp://1.1.1.1:53".to_string()],
        ..Default::default()
    }
}

fn conditional_pool(name: &str, domains: &[&str], groups: &[i64]) -> UpstreamPool {
    UpstreamPool {
        name: name.to_string(),
        servers: vec!["udp://10.0.0.10:53".to_string()],
        domains: domains.iter().map(|d| d.to_string()).collect(),
        groups: groups.to_vec(),
        ..Default::default()
    }
}

fn route_error(pools: &[UpstreamPool]) -> String {
    match validate_pool_routes(pools) {
        Err(DomainError::ConfigError(message)) => message,
        other => panic!("expected a configuration error, got {other:?}"),
    }
}

#[test]
fn test_normalize_route_domain_converts_unicode_to_punycode() {
    assert_eq!(normalize_route_domain("рф").unwrap(), "xn--p1ai");
    assert_eq!(
        normalize_route_domain("пример.рф").unwrap(),
        "xn--e1afmkfd.xn--p1ai"
    );
}

#[test]
fn test_normalize_route_domain_lowercases_and_trims_dots_and_spaces() {
    assert_eq!(
        normalize_route_domain("Corp.Example.").unwrap(),
        "corp.example"
    );
    assert_eq!(
        normalize_route_domain(".corp.example").unwrap(),
        "corp.example"
    );
    assert_eq!(normalize_route_domain("  lan  ").unwrap(), "lan");
}

#[test]
fn test_normalize_route_domain_accepts_reverse_zones_and_service_labels() {
    assert_eq!(
        normalize_route_domain("1.10.in-addr.arpa").unwrap(),
        "1.10.in-addr.arpa"
    );
    assert_eq!(
        normalize_route_domain("_msdcs.corp.example").unwrap(),
        "_msdcs.corp.example"
    );
}

#[test]
fn test_normalize_route_domain_rejects_invalid_names() {
    for invalid in ["", ".", "*.corp", "corp..example", "bad domain", "a/b"] {
        assert!(
            normalize_route_domain(invalid).is_err(),
            "{invalid:?} must be rejected"
        );
    }
}

#[test]
fn test_validate_pool_routes_accepts_no_pools_and_default_pools_only() {
    validate_pool_routes(&[]).unwrap();
    validate_pool_routes(&[default_pool()]).unwrap();
}

#[test]
fn test_validate_pool_routes_accepts_global_and_group_routes() {
    let pools = [
        default_pool(),
        conditional_pool("gov", &["ru", "рф", "su"], &[]),
        conditional_pool("office-a", &["corp.example"], &[3]),
        conditional_pool("office-b", &["corp.example"], &[4]),
        conditional_pool("corp-default", &["corp.example"], &[]),
    ];
    validate_pool_routes(&pools).unwrap();
}

#[test]
fn test_validate_pool_routes_requires_a_default_pool() {
    let message = route_error(&[conditional_pool("gov", &["ru"], &[])]);
    assert!(
        message.contains("At least one pool must have no domains"),
        "{message}"
    );
}

#[test]
fn test_validate_pool_routes_rejects_groups_without_domains() {
    let mut pool = default_pool();
    pool.groups = vec![3];
    let message = route_error(&[pool]);
    assert!(message.contains("sets groups without domains"), "{message}");
}

#[test]
fn test_validate_pool_routes_rejects_internal_without_domains() {
    let mut pool = default_pool();
    pool.internal = true;
    let message = route_error(&[pool]);
    assert!(message.contains("is internal without domains"), "{message}");
}

#[test]
fn test_validate_pool_routes_rejects_group_ids_outside_u32() {
    for id in [0, -1, i64::from(u32::MAX) + 1] {
        let message = route_error(&[default_pool(), conditional_pool("x", &["corp"], &[id])]);
        assert!(
            message.contains("is not a client group id"),
            "{id}: {message}"
        );
    }
}

#[test]
fn test_validate_pool_routes_rejects_invalid_domain_naming_the_pool() {
    let message = route_error(&[default_pool(), conditional_pool("office", &["*.corp"], &[])]);
    assert!(message.contains("Pool 'office'"), "{message}");
    assert!(message.contains("'*.corp'"), "{message}");
}

#[test]
fn test_validate_pool_routes_rejects_a_domain_claimed_twice_for_every_client() {
    let message = route_error(&[
        default_pool(),
        conditional_pool("a", &["corp.example"], &[]),
        conditional_pool("b", &["Corp.Example."], &[]),
    ]);
    assert!(message.contains("'corp.example'"), "{message}");
    assert!(message.contains("every client"), "{message}");
}

#[test]
fn test_validate_pool_routes_rejects_unicode_and_punycode_of_the_same_domain() {
    let message = route_error(&[
        default_pool(),
        conditional_pool("a", &["рф"], &[]),
        conditional_pool("b", &["xn--p1ai"], &[]),
    ]);
    assert!(message.contains("'xn--p1ai'"), "{message}");
}

#[test]
fn test_validate_pool_routes_rejects_a_domain_claimed_twice_for_the_same_group() {
    let message = route_error(&[
        default_pool(),
        conditional_pool("a", &["corp.example"], &[3, 4]),
        conditional_pool("b", &["corp.example"], &[4]),
    ]);
    assert!(message.contains("client group 4"), "{message}");
}

#[test]
fn test_validate_pool_routes_allows_a_domain_repeated_in_the_same_pool() {
    validate_pool_routes(&[
        default_pool(),
        conditional_pool("a", &["corp.example", "CORP.example"], &[]),
    ])
    .unwrap();
}

#[test]
fn test_config_validate_checks_pool_routes() {
    let mut config = Config::default();
    config.dns.pools = vec![conditional_pool("gov", &["ru"], &[])];
    assert!(matches!(
        config.validate(),
        Err(DomainError::ConfigError(_))
    ));
}

const BASE_TOML: &str = r#"
[server]
dns_port = 53
web_port = 8080
bind_address = "0.0.0.0"

[blocking]
enabled = true

[logging]
level = "info"

[database]
"#;

#[test]
fn test_pool_without_routing_fields_parses_as_a_default_pool() {
    let toml = format!(
        "{BASE_TOML}\n[dns]\n[[dns.pools]]\nname = \"p\"\nstrategy = \"Parallel\"\nservers = [\"1.1.1.1:53\"]\n"
    );
    let config = Config::from_toml_str(&toml).unwrap();
    config.validate().unwrap();
    let pool = &config.dns.pools[0];
    assert!(pool.domains.is_empty());
    assert!(pool.groups.is_empty());
    assert!(!pool.internal);
    assert!(!pool.is_conditional());
}

#[test]
fn test_pool_routing_fields_parse_from_toml() {
    let toml = format!(
        r#"{BASE_TOML}
[dns]
[[dns.pools]]
name = "public"
strategy = "Parallel"
servers = ["1.1.1.1:53"]

[[dns.pools]]
name = "office-a"
strategy = "Failover"
servers = ["udp://10.1.0.10:53"]
domains = ["corp.example", "рф"]
groups = [3]
internal = true
"#
    );
    let config = Config::from_toml_str(&toml).unwrap();
    config.validate().unwrap();
    let pool = &config.dns.pools[1];
    assert_eq!(pool.domains, ["corp.example", "рф"]);
    assert_eq!(pool.groups, [3]);
    assert!(pool.internal);
    assert_eq!(
        pool.normalized_domains().unwrap(),
        ["corp.example", "xn--p1ai"]
    );
}
