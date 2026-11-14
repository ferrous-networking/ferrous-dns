use ferrous_dns_domain::ApiToken;

#[test]
fn validate_name_accepts_alphanumeric() {
    assert!(ApiToken::validate_name("my-token").is_ok());
    assert!(ApiToken::validate_name("Token 123").is_ok());
    assert!(ApiToken::validate_name("under_score").is_ok());
    assert!(ApiToken::validate_name("A").is_ok());
}

#[test]
fn validate_name_rejects_empty() {
    assert!(ApiToken::validate_name("").is_err());
}

#[test]
fn validate_name_rejects_too_long() {
    let long = "a".repeat(101);
    assert!(ApiToken::validate_name(&long).is_err());
}

#[test]
fn validate_name_accepts_exactly_100_chars() {
    let name = "a".repeat(100);
    assert!(ApiToken::validate_name(&name).is_ok());
}

#[test]
fn validate_name_rejects_special_characters() {
    assert!(ApiToken::validate_name("token!").is_err());
    assert!(ApiToken::validate_name("token@home").is_err());
    assert!(ApiToken::validate_name("token#1").is_err());
    assert!(ApiToken::validate_name("to/ken").is_err());
    assert!(ApiToken::validate_name("tok.en").is_err());
}

#[test]
fn validate_name_returns_domain_error() {
    let err = ApiToken::validate_name("").unwrap_err();
    assert!(
        matches!(err, ferrous_dns_domain::DomainError::InvalidInput(_)),
        "expected InvalidInput, got: {err:?}"
    );
}

#[test]
fn test_validate_custom_key_needs_32_characters() {
    assert!(ApiToken::validate_custom_key(&"k".repeat(31)).is_err());
    assert!(ApiToken::validate_custom_key(&"k".repeat(32)).is_ok());
}

/// Characters, not bytes: 16 two-byte characters are 32 bytes but 16 characters.
#[test]
fn test_validate_custom_key_counts_characters() {
    assert!(ApiToken::validate_custom_key(&"é".repeat(16)).is_err());
    assert!(ApiToken::validate_custom_key(&"é".repeat(32)).is_ok());
}

/// HTTP strips a header value's surrounding whitespace, so such a key could
/// never be sent as `X-Api-Key`; the dashboard trims it before it counts.
#[test]
fn test_validate_custom_key_refuses_surrounding_whitespace() {
    assert!(ApiToken::validate_custom_key(&" ".repeat(32)).is_err());
    assert!(ApiToken::validate_custom_key(&format!(" {} ", "k".repeat(30))).is_err());
    assert!(ApiToken::validate_custom_key(&format!("{}\t", "k".repeat(32))).is_err());
}

#[test]
fn test_validate_custom_key_accepts_inner_spaces() {
    assert!(ApiToken::validate_custom_key("correct horse battery staple 2026").is_ok());
}
