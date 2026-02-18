use ferrous_dns_api::utils::{parse_period, validate_period};

#[test]
fn test_parse_period_hours() {
    assert_eq!(parse_period("1h"), Some(1.0));
    assert_eq!(parse_period("24h"), Some(24.0));
    assert_eq!(parse_period("48h"), Some(48.0));
    assert_eq!(parse_period("720h"), Some(720.0));
}

#[test]
fn test_parse_period_minutes() {
    assert_eq!(parse_period("30m"), Some(0.5));
    assert_eq!(parse_period("60m"), Some(1.0));
    assert_eq!(parse_period("90m"), Some(1.5));
    assert_eq!(parse_period("120m"), Some(2.0));
}

#[test]
fn test_parse_period_days() {
    assert_eq!(parse_period("1d"), Some(24.0));
    assert_eq!(parse_period("7d"), Some(168.0));
    assert_eq!(parse_period("30d"), Some(720.0));
}

#[test]
fn test_parse_period_weeks() {
    assert_eq!(parse_period("1w"), Some(168.0));
    assert_eq!(parse_period("2w"), Some(336.0));
    assert_eq!(parse_period("4w"), Some(672.0));
}

#[test]
fn test_parse_period_empty_defaults_to_24h() {
    assert_eq!(parse_period(""), Some(24.0));
}

#[test]
fn test_parse_period_invalid_formats() {
    assert_eq!(parse_period("invalid"), None);
    assert_eq!(parse_period("24x"), None);
    assert_eq!(parse_period("h"), None);
    assert_eq!(parse_period("m"), None);
    assert_eq!(parse_period("abc123"), None);
    assert_eq!(parse_period("123"), None);
}

#[test]
fn test_parse_period_edge_cases() {
    assert_eq!(parse_period("0h"), None);
    assert_eq!(parse_period("0.5h"), Some(0.5));
    assert_eq!(parse_period("-1h"), None);
}

#[test]
fn test_validate_period_within_limits() {
    assert_eq!(validate_period(1.0), 1.0);
    assert_eq!(validate_period(24.0), 24.0);
    assert_eq!(validate_period(168.0), 168.0);
    assert_eq!(validate_period(720.0), 720.0);
}

#[test]
fn test_validate_period_caps_at_30_days() {
    assert_eq!(validate_period(721.0), 720.0);
    assert_eq!(validate_period(1000.0), 720.0);
    assert_eq!(validate_period(10000.0), 720.0);
}

#[test]
fn test_validate_period_edge_cases() {
    assert_eq!(validate_period(0.0), 0.0);
    assert_eq!(validate_period(0.5), 0.5);
}

#[test]
fn test_common_period_combinations() {
    let periods = vec!["30m", "1h", "6h", "12h", "24h", "7d", "30d"];

    for period in periods {
        let parsed = parse_period(period);
        assert!(parsed.is_some(), "Failed to parse period: {}", period);

        let validated = validate_period(parsed.unwrap());
        assert!(validated <= 720.0, "Period {} exceeds maximum", period);
    }
}

#[test]
fn test_period_format_consistency() {
    assert_eq!(parse_period("1d"), parse_period("24h"));

    assert_eq!(parse_period("1w"), parse_period("7d"));

    assert_eq!(parse_period("60m"), parse_period("1h"));
}

#[test]
fn test_period_parsing_performance() {
    for _ in 0..10000 {
        let _ = parse_period("24h");
        let _ = parse_period("7d");
        let _ = validate_period(168.0);
    }
}
