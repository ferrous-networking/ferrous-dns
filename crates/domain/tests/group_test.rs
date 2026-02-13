use ferrous_dns_domain::Group;
use std::sync::Arc;

#[test]
fn test_group_creation() {
    let group = Group::new(
        Some(1),
        Arc::from("Test Group"),
        true,
        Some(Arc::from("Test comment")),
        false,
    );

    assert_eq!(group.id, Some(1));
    assert_eq!(group.name.as_ref(), "Test Group");
    assert!(group.enabled);
    assert_eq!(
        group.comment.as_ref().map(|s| s.as_ref()),
        Some("Test comment")
    );
    assert!(!group.is_default);
}

#[test]
fn test_validate_name_valid() {
    assert!(Group::validate_name("Valid Name").is_ok());
    assert!(Group::validate_name("Test-Group_123").is_ok());
    assert!(Group::validate_name("A").is_ok());
}

#[test]
fn test_validate_name_empty() {
    assert!(Group::validate_name("").is_err());
}

#[test]
fn test_validate_name_too_long() {
    let long_name = "a".repeat(101);
    assert!(Group::validate_name(&long_name).is_err());
}

#[test]
fn test_validate_name_invalid_characters() {
    assert!(Group::validate_name("Invalid@Name").is_err());
    assert!(Group::validate_name("Name!With#Special$").is_err());
}

#[test]
fn test_validate_comment_valid() {
    let valid_comment = Some(Arc::from("Valid comment"));
    assert!(Group::validate_comment(&valid_comment).is_ok());
}

#[test]
fn test_validate_comment_none() {
    assert!(Group::validate_comment(&None).is_ok());
}

#[test]
fn test_validate_comment_too_long() {
    let long_comment = Some(Arc::from("a".repeat(501).as_str()));
    assert!(Group::validate_comment(&long_comment).is_err());
}

#[test]
fn test_can_disable_regular_group() {
    let group = Group::new(None, Arc::from("Regular"), true, None, false);
    assert!(group.can_disable());
}

#[test]
fn test_cannot_disable_default_group() {
    let group = Group::new(None, Arc::from("Protected"), true, None, true);
    assert!(!group.can_disable());
}

#[test]
fn test_can_delete_regular_group() {
    let group = Group::new(None, Arc::from("Regular"), true, None, false);
    assert!(group.can_delete());
}

#[test]
fn test_cannot_delete_default_group() {
    let group = Group::new(None, Arc::from("Protected"), true, None, true);
    assert!(!group.can_delete());
}

#[test]
fn test_default_group_properties() {
    let protected_group = Group::new(
        Some(1),
        Arc::from("Protected"),
        true,
        Some(Arc::from(
            "Default group for all clients. Cannot be disabled or deleted.",
        )),
        true,
    );

    assert_eq!(protected_group.id, Some(1));
    assert_eq!(protected_group.name.as_ref(), "Protected");
    assert!(protected_group.enabled);
    assert!(protected_group.is_default);
    assert!(!protected_group.can_disable());
    assert!(!protected_group.can_delete());
}
