use ferrous_dns_domain::WhitelistSource;
use std::sync::Arc;

#[test]
fn test_whitelist_source_creation() {
    let source = WhitelistSource::new(
        Some(1),
        Arc::from("Test Allowlist"),
        Some(Arc::from("https://example.com/allowlist.txt")),
        1,
        Some(Arc::from("Test comment")),
        true,
    );

    assert_eq!(source.id, Some(1));
    assert_eq!(source.name.as_ref(), "Test Allowlist");
    assert_eq!(
        source.url.as_deref(),
        Some("https://example.com/allowlist.txt")
    );
    assert_eq!(source.group_id, 1);
    assert_eq!(source.comment.as_deref(), Some("Test comment"));
    assert!(source.enabled);
    assert!(source.created_at.is_none());
    assert!(source.updated_at.is_none());
}

#[test]
fn test_whitelist_source_no_url_no_comment() {
    let source = WhitelistSource::new(None, Arc::from("Manual Allowlist"), None, 1, None, false);

    assert!(source.id.is_none());
    assert_eq!(source.name.as_ref(), "Manual Allowlist");
    assert!(source.url.is_none());
    assert!(source.comment.is_none());
    assert!(!source.enabled);
}

#[test]
fn test_validate_name_valid() {
    assert!(WhitelistSource::validate_name("Valid Name").is_ok());
    assert!(WhitelistSource::validate_name("A").is_ok());
    assert!(WhitelistSource::validate_name("AdGuard DNS Allowlist").is_ok());
    assert!(WhitelistSource::validate_name("list-1_v2.txt").is_ok());
}

#[test]
fn test_validate_name_empty() {
    let result = WhitelistSource::validate_name("");
    assert!(result.is_err());
}

#[test]
fn test_validate_name_too_long() {
    let long_name = "a".repeat(201);
    let result = WhitelistSource::validate_name(&long_name);
    assert!(result.is_err());
}

#[test]
fn test_validate_name_exactly_200_chars() {
    let name = "a".repeat(200);
    assert!(WhitelistSource::validate_name(&name).is_ok());
}

#[test]
fn test_validate_url_valid_https() {
    let url = Some(Arc::from("https://example.com/allowlist.txt"));
    assert!(WhitelistSource::validate_url(&url).is_ok());
}

#[test]
fn test_validate_url_valid_http() {
    let url = Some(Arc::from("http://example.com/allowlist.txt"));
    assert!(WhitelistSource::validate_url(&url).is_ok());
}

#[test]
fn test_validate_url_invalid_scheme_ftp() {
    let url = Some(Arc::from("ftp://example.com/list.txt"));
    let result = WhitelistSource::validate_url(&url);
    assert!(result.is_err());
}

#[test]
fn test_validate_url_no_scheme() {
    let url = Some(Arc::from("example.com/list.txt"));
    let result = WhitelistSource::validate_url(&url);
    assert!(result.is_err());
}

#[test]
fn test_validate_url_none() {
    assert!(WhitelistSource::validate_url(&None).is_ok());
}

#[test]
fn test_validate_url_too_long() {
    let long_url = format!("https://example.com/{}", "a".repeat(2048));
    let url = Some(Arc::from(long_url.as_str()));
    let result = WhitelistSource::validate_url(&url);
    assert!(result.is_err());
}

#[test]
fn test_validate_url_exactly_2048_chars() {
    let prefix = "https://x.com/";
    let path = "a".repeat(2048 - prefix.len());
    let url_str = format!("{}{}", prefix, path);
    assert_eq!(url_str.len(), 2048);
    let url = Some(Arc::from(url_str.as_str()));
    assert!(WhitelistSource::validate_url(&url).is_ok());
}

#[test]
fn test_validate_comment_valid() {
    let comment = Some(Arc::from("A valid comment"));
    assert!(WhitelistSource::validate_comment(&comment).is_ok());
}

#[test]
fn test_validate_comment_none() {
    assert!(WhitelistSource::validate_comment(&None).is_ok());
}

#[test]
fn test_validate_comment_too_long() {
    let long_comment = Some(Arc::from("a".repeat(501).as_str()));
    let result = WhitelistSource::validate_comment(&long_comment);
    assert!(result.is_err());
}

#[test]
fn test_validate_comment_exactly_500_chars() {
    let comment = Some(Arc::from("a".repeat(500).as_str()));
    assert!(WhitelistSource::validate_comment(&comment).is_ok());
}
