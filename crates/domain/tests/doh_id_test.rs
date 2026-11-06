use ferrous_dns_domain::DohId;

#[test]
fn test_doh_id_validate_name_accepts_valid_names() {
    assert!(DohId::validate_name("Alice's iPhone").is_ok());
    assert!(DohId::validate_name("Work Laptop (MacBook)").is_ok());
    assert!(DohId::validate_name("a").is_ok());
    assert!(DohId::validate_name(&"x".repeat(100)).is_ok());
}

#[test]
fn test_doh_id_validate_name_rejects_empty_or_whitespace() {
    assert!(DohId::validate_name("")
        .unwrap_err()
        .contains("cannot be empty"));
    assert!(DohId::validate_name("   \t\n ")
        .unwrap_err()
        .contains("cannot be empty"));
}

#[test]
fn test_doh_id_validate_name_rejects_over_100_chars() {
    let long_name = "x".repeat(101);
    assert!(DohId::validate_name(&long_name)
        .unwrap_err()
        .contains("cannot exceed 100 characters"));
}

#[test]
fn test_doh_id_validate_client_id_accepts_uuid_and_readable_ids() {
    assert!(DohId::validate_client_id("550e8400-e29b-41d4-a716-446655440000").is_ok());
    assert!(DohId::validate_client_id("alice-iphone").is_ok());
    assert!(DohId::validate_client_id("kids-ipad-2").is_ok());
    assert!(DohId::validate_client_id("a").is_ok());
    assert!(DohId::validate_client_id("0").is_ok());
    assert!(DohId::validate_client_id(&"a".repeat(63)).is_ok());
}

#[test]
fn test_doh_id_validate_client_id_rejects_empty_and_overlong() {
    assert!(DohId::validate_client_id("")
        .unwrap_err()
        .contains("cannot be empty"));
    assert!(DohId::validate_client_id(&"a".repeat(64))
        .unwrap_err()
        .contains("cannot exceed 63 characters"));
}

#[test]
fn test_doh_id_validate_client_id_rejects_invalid_characters() {
    assert!(DohId::validate_client_id("Alice-Phone").is_err());
    assert!(DohId::validate_client_id("alice_phone").is_err());
    assert!(DohId::validate_client_id("alice.phone").is_err());
    assert!(DohId::validate_client_id("alice/phone").is_err());
    assert!(DohId::validate_client_id("alice phone").is_err());
    assert!(DohId::validate_client_id("아이폰").is_err());
}

#[test]
fn test_doh_id_validate_client_id_rejects_leading_or_trailing_hyphen() {
    assert!(DohId::validate_client_id("-alice")
        .unwrap_err()
        .contains("cannot start or end with a hyphen"));
    assert!(DohId::validate_client_id("alice-")
        .unwrap_err()
        .contains("cannot start or end with a hyphen"));
    assert!(DohId::validate_client_id("-")
        .unwrap_err()
        .contains("cannot start or end with a hyphen"));
}
