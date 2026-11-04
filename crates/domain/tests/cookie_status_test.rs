use ferrous_dns_domain::{BlockSource, CookieFilter, CookieStatus};

#[test]
fn test_cookie_status_names_round_trip() {
    for status in [
        CookieStatus::ClientOnly,
        CookieStatus::Valid,
        CookieStatus::Invalid,
    ] {
        assert_eq!(status.as_str().parse::<CookieStatus>().ok(), Some(status));
    }
    assert!("Valid".parse::<CookieStatus>().is_err());
}

#[test]
fn test_cookie_filter_parses_every_api_value() {
    for (text, filter) in [
        ("any", CookieFilter::Any),
        ("valid", CookieFilter::Status(CookieStatus::Valid)),
        ("client", CookieFilter::Status(CookieStatus::ClientOnly)),
        ("invalid", CookieFilter::Status(CookieStatus::Invalid)),
        ("none", CookieFilter::Without),
    ] {
        assert_eq!(text.parse::<CookieFilter>().ok(), Some(filter), "{text}");
    }
    let error = "stale".parse::<CookieFilter>().unwrap_err();
    assert!(error.to_string().contains("cookie filter"), "{error}");
}

#[test]
fn test_dns_cookie_block_source_is_a_policy_block() {
    assert_eq!(BlockSource::DnsCookie.to_str(), "dns_cookie");
    assert_eq!(
        "dns_cookie".parse::<BlockSource>().ok(),
        Some(BlockSource::DnsCookie)
    );
    assert!(!BlockSource::DnsCookie.is_malware());
}
