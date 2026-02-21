use axum::http::Method;
use ferrous_dns_api::middleware::{is_read_only_method, timing_safe_eq};

#[test]
fn test_timing_safe_eq_equal_strings() {
    assert!(timing_safe_eq(b"secret", b"secret"));
}

#[test]
fn test_timing_safe_eq_different_strings() {
    assert!(!timing_safe_eq(b"secret", b"wrong!"));
}

#[test]
fn test_timing_safe_eq_different_lengths() {
    assert!(!timing_safe_eq(b"short", b"longer-value"));
}

#[test]
fn test_timing_safe_eq_empty_strings() {
    assert!(timing_safe_eq(b"", b""));
}

#[test]
fn test_get_is_read_only() {
    assert!(is_read_only_method(&Method::GET));
}

#[test]
fn test_head_is_read_only() {
    assert!(is_read_only_method(&Method::HEAD));
}

#[test]
fn test_options_is_read_only() {
    assert!(is_read_only_method(&Method::OPTIONS));
}

#[test]
fn test_post_is_mutation() {
    assert!(!is_read_only_method(&Method::POST));
}

#[test]
fn test_put_is_mutation() {
    assert!(!is_read_only_method(&Method::PUT));
}

#[test]
fn test_delete_is_mutation() {
    assert!(!is_read_only_method(&Method::DELETE));
}
