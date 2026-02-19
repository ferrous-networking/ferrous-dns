use ferrous_dns_domain::{DomainAction, ManagedDomain};
use std::str::FromStr;
use std::sync::Arc;

#[test]
fn test_managed_domain_creation() {
    let domain = ManagedDomain::new(
        Some(1),
        Arc::from("Block Ads"),
        Arc::from("ads.example.com"),
        DomainAction::Deny,
        1,
        Some(Arc::from("Test comment")),
        true,
    );

    assert_eq!(domain.id, Some(1));
    assert_eq!(domain.name.as_ref(), "Block Ads");
    assert_eq!(domain.domain.as_ref(), "ads.example.com");
    assert_eq!(domain.action, DomainAction::Deny);
    assert_eq!(domain.group_id, 1);
    assert_eq!(domain.comment.as_deref(), Some("Test comment"));
    assert!(domain.enabled);
    assert!(domain.created_at.is_none());
    assert!(domain.updated_at.is_none());
}

#[test]
fn test_managed_domain_allow_no_comment() {
    let domain = ManagedDomain::new(
        None,
        Arc::from("Allow Company"),
        Arc::from("mycompany.com"),
        DomainAction::Allow,
        2,
        None,
        false,
    );

    assert!(domain.id.is_none());
    assert_eq!(domain.action, DomainAction::Allow);
    assert!(domain.comment.is_none());
    assert!(!domain.enabled);
}

// ── validate_name ─────────────────────────────────────────────────────────────

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
fn test_validate_name_exactly_200_chars() {
    let name = "a".repeat(200);
    assert!(ManagedDomain::validate_name(&name).is_ok());
}

// ── validate_domain ───────────────────────────────────────────────────────────

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

// ── validate_comment ──────────────────────────────────────────────────────────

#[test]
fn test_validate_comment_valid() {
    let comment = Some(Arc::from("A valid comment"));
    assert!(ManagedDomain::validate_comment(&comment).is_ok());
}

#[test]
fn test_validate_comment_none() {
    assert!(ManagedDomain::validate_comment(&None).is_ok());
}

#[test]
fn test_validate_comment_too_long() {
    let long_comment = Some(Arc::from("a".repeat(501).as_str()));
    assert!(ManagedDomain::validate_comment(&long_comment).is_err());
}

#[test]
fn test_validate_comment_exactly_500_chars() {
    let comment = Some(Arc::from("a".repeat(500).as_str()));
    assert!(ManagedDomain::validate_comment(&comment).is_ok());
}

// ── DomainAction ──────────────────────────────────────────────────────────────

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
