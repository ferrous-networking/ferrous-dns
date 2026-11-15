use ferrous_dns_domain::{DomainAction, ManagedDomain};
use std::str::FromStr;

#[test]
fn test_validate_name_valid() {
    assert!(ManagedDomain::validate_name("Block Ads").is_ok());
    assert!(ManagedDomain::validate_name("A").is_ok());
    assert!(ManagedDomain::validate_name("rule-1_v2").is_ok());
}

#[test]
fn test_validate_name_empty() {
    assert!(ManagedDomain::validate_name("").is_err());
}

#[test]
fn test_validate_name_too_long() {
    let long_name = "a".repeat(201);
    assert!(ManagedDomain::validate_name(&long_name).is_err());
}

#[test]
fn test_fallback_name_appends_the_action() {
    assert_eq!(
        ManagedDomain::fallback_name("ads.example.com", DomainAction::Allow),
        "ads.example.com (allow)"
    );
    assert_eq!(
        ManagedDomain::fallback_name("*.ads.example.com", DomainAction::Deny),
        "*.ads.example.com (deny)"
    );
}

#[test]
fn test_validate_name_exactly_200_chars() {
    let name = "a".repeat(200);
    assert!(ManagedDomain::validate_name(&name).is_ok());
}

#[test]
fn test_validate_domain_valid() {
    assert!(ManagedDomain::validate_domain("ads.example.com").is_ok());
    assert!(ManagedDomain::validate_domain("example.com").is_ok());
    assert!(ManagedDomain::validate_domain("sub.domain.example.org").is_ok());
    assert!(ManagedDomain::validate_domain("*.example.com").is_ok());
}

#[test]
fn test_validate_domain_empty() {
    assert!(ManagedDomain::validate_domain("").is_err());
}

#[test]
fn test_validate_domain_too_long() {
    let long_domain = format!("{}.com", "a".repeat(250));
    assert!(ManagedDomain::validate_domain(&long_domain).is_err());
}

#[test]
fn test_validate_domain_exactly_253_chars() {
    // 249 chars + ".com" = 253
    let domain = format!("{}.com", "a".repeat(249));
    assert_eq!(domain.len(), 253);
    assert!(ManagedDomain::validate_domain(&domain).is_ok());
}

#[test]
fn test_validate_domain_invalid_chars() {
    assert!(ManagedDomain::validate_domain("ads example.com").is_err());
    assert!(ManagedDomain::validate_domain("ads/example.com").is_err());
    assert!(ManagedDomain::validate_domain("ads@example.com").is_err());
}

#[test]
fn test_validate_domain_wildcard_valid() {
    // "*.suffix" prefix is the only valid wildcard form
    assert!(ManagedDomain::validate_domain("*.x.com").is_ok());
    assert!(ManagedDomain::validate_domain("*.example.org").is_ok());
    assert!(ManagedDomain::validate_domain("*.sub.domain.com").is_ok());
}

#[test]
fn test_validate_domain_wildcard_invalid() {
    // "*" without "." prefix must be rejected
    assert!(ManagedDomain::validate_domain("*x.com").is_err());
    assert!(ManagedDomain::validate_domain("x.*.com").is_err());
    assert!(ManagedDomain::validate_domain("x.com*").is_err());
    assert!(ManagedDomain::validate_domain("*").is_err());
}

#[test]
fn test_domain_action_from_str_allow() {
    assert_eq!(
        DomainAction::from_str("allow").ok(),
        Some(DomainAction::Allow)
    );
}

#[test]
fn test_domain_action_from_str_deny() {
    assert_eq!(
        DomainAction::from_str("deny").ok(),
        Some(DomainAction::Deny)
    );
}

#[test]
fn test_domain_action_from_str_invalid() {
    assert!(DomainAction::from_str("block").is_err());
    assert!(DomainAction::from_str("").is_err());
    assert!(DomainAction::from_str("ALLOW").is_err());
}

#[test]
fn test_domain_action_to_str() {
    assert_eq!(DomainAction::Allow.to_str(), "allow");
    assert_eq!(DomainAction::Deny.to_str(), "deny");
}

#[test]
fn test_validate_domain_rejects_empty_labels() {
    for domain in ["*.", ".", "*..", ".example.com", "ads..example.com"] {
        assert!(
            ManagedDomain::validate_domain(domain).is_err(),
            "{domain:?} accepted"
        );
    }
    assert!(ManagedDomain::validate_domain("*.example.com").is_ok());
}
