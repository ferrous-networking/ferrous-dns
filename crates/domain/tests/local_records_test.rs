use ferrous_dns_domain::LocalDnsRecord;

fn record(hostname: &str, domain: Option<&str>) -> LocalDnsRecord {
    LocalDnsRecord {
        hostname: hostname.to_string(),
        domain: domain.map(str::to_string),
        ip: "192.168.1.10".to_string(),
        record_type: "A".to_string(),
        ttl: None,
    }
}

#[test]
fn test_validate_hostname_accepts_plain_names() {
    assert!(LocalDnsRecord::validate_hostname("nas").is_ok());
    assert!(LocalDnsRecord::validate_hostname("www-1").is_ok());
    assert!(LocalDnsRecord::validate_hostname("my_host").is_ok());
    assert!(LocalDnsRecord::validate_hostname("app.internal").is_ok());
}

#[test]
fn test_validate_hostname_accepts_leftmost_wildcard() {
    assert!(LocalDnsRecord::validate_hostname("*").is_ok());
    assert!(LocalDnsRecord::validate_hostname("*.dev").is_ok());
}

#[test]
fn test_validate_hostname_rejects_misplaced_wildcard() {
    assert!(LocalDnsRecord::validate_hostname("a.*.b").is_err());
    assert!(LocalDnsRecord::validate_hostname("*x").is_err());
    assert!(LocalDnsRecord::validate_hostname("dev.*").is_err());
}

#[test]
fn test_validate_hostname_rejects_empty() {
    assert!(LocalDnsRecord::validate_hostname("").is_err());
}

#[test]
fn test_validate_hostname_rejects_empty_label() {
    assert!(LocalDnsRecord::validate_hostname("foo..bar").is_err());
    assert!(LocalDnsRecord::validate_hostname(".foo").is_err());
    assert!(LocalDnsRecord::validate_hostname("foo.").is_err());
}

#[test]
fn test_validate_hostname_rejects_oversized_label() {
    let label = "a".repeat(64);
    assert!(LocalDnsRecord::validate_hostname(&label).is_err());
}

#[test]
fn test_validate_hostname_rejects_invalid_characters() {
    assert!(LocalDnsRecord::validate_hostname("my host").is_err());
    assert!(LocalDnsRecord::validate_hostname("host!").is_err());
    assert!(LocalDnsRecord::validate_hostname("héllo").is_err());
}

#[test]
fn test_validate_domain_rejects_wildcard() {
    assert!(LocalDnsRecord::validate_domain("example.com").is_ok());
    assert!(LocalDnsRecord::validate_domain("*.example.com").is_err());
    assert!(LocalDnsRecord::validate_domain("").is_err());
}

#[test]
fn test_is_wildcard_follows_hostname() {
    assert!(record("*", Some("home.lan")).is_wildcard());
    assert!(record("*.dev", Some("home.lan")).is_wildcard());
    assert!(!record("nas", Some("home.lan")).is_wildcard());
}

#[test]
fn test_wildcard_suffix_strips_the_star_label() {
    assert_eq!(
        record("*", Some("home.lan")).wildcard_suffix(&None),
        Some("home.lan".to_string())
    );
    assert_eq!(
        record("*.dev", Some("home.lan")).wildcard_suffix(&None),
        Some("dev.home.lan".to_string())
    );
}

#[test]
fn test_wildcard_suffix_uses_the_default_domain() {
    assert_eq!(
        record("*", None).wildcard_suffix(&Some("lan".to_string())),
        Some("lan".to_string())
    );
}

#[test]
fn test_wildcard_suffix_is_lowercased() {
    assert_eq!(
        record("*", Some("HOME.LAN")).wildcard_suffix(&None),
        Some("home.lan".to_string())
    );
}

#[test]
fn test_wildcard_suffix_none_without_a_domain_to_anchor_it() {
    assert_eq!(record("*", None).wildcard_suffix(&None), None);
}

#[test]
fn test_wildcard_suffix_none_for_an_exact_record() {
    assert_eq!(record("nas", Some("home.lan")).wildcard_suffix(&None), None);
}
