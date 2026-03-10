use ferrous_dns_infrastructure::dns::tunneling::entropy::{
    extract_apex, extract_subdomain, shannon_entropy,
};

// ── Shannon entropy ─────────────────────────────────────────────────────────

#[test]
fn entropy_of_english_word_is_low() {
    let e = shannon_entropy(b"google");
    assert!(e < 2.6, "expected < 2.6, got {e}");
}

#[test]
fn entropy_of_hex_string_is_high() {
    let e = shannon_entropy(b"a3f8d2e1b7c4a9f0");
    assert!(e > 3.5, "expected > 3.5, got {e}");
}

#[test]
fn entropy_of_base64_is_high() {
    let e = shannon_entropy(b"dGhpcyBpcyBhIHRlc3Q=");
    assert!(e > 3.0, "expected > 3.0, got {e}");
}

#[test]
fn empty_input_returns_zero() {
    assert_eq!(shannon_entropy(b""), 0.0);
}

#[test]
fn single_repeated_char_returns_zero() {
    assert_eq!(shannon_entropy(b"aaaa"), 0.0);
}

#[test]
fn two_equal_chars_returns_one_bit() {
    let e = shannon_entropy(b"ab");
    assert!((e - 1.0).abs() < 0.01, "expected ~1.0, got {e}");
}

#[test]
fn entropy_increases_with_alphabet_size() {
    let low = shannon_entropy(b"aabb");
    let high = shannon_entropy(b"abcd");
    assert!(high > low, "expected {high} > {low}");
}

#[test]
fn real_tunneling_subdomain_has_high_entropy() {
    // Typical base32-encoded tunneling payload
    let e = shannon_entropy(b"mfzwizltoq2gk3djorugk");
    assert!(e > 3.0, "expected > 3.0, got {e}");
}

#[test]
fn normal_subdomain_has_low_entropy() {
    let e = shannon_entropy(b"www");
    assert!(e < 2.0, "expected < 2.0, got {e}");
}

// ── extract_subdomain ───────────────────────────────────────────────────────

#[test]
fn extract_subdomain_returns_none_for_apex() {
    assert_eq!(extract_subdomain("example.com"), None);
}

#[test]
fn extract_subdomain_returns_none_for_single_label() {
    assert_eq!(extract_subdomain("localhost"), None);
}

#[test]
fn extract_subdomain_returns_single_label_before_apex() {
    assert_eq!(extract_subdomain("sub.example.com"), Some("sub"));
}

#[test]
fn extract_subdomain_returns_multiple_labels_before_apex() {
    assert_eq!(extract_subdomain("foo.bar.example.com"), Some("foo.bar"));
}

#[test]
fn extract_subdomain_deeply_nested() {
    assert_eq!(extract_subdomain("a.b.c.d.example.com"), Some("a.b.c.d"));
}

// ── extract_apex ────────────────────────────────────────────────────────────

#[test]
fn extract_apex_two_labels() {
    assert_eq!(extract_apex("example.com"), "example.com");
}

#[test]
fn extract_apex_three_labels() {
    assert_eq!(extract_apex("sub.example.com"), "example.com");
}

#[test]
fn extract_apex_many_labels() {
    assert_eq!(extract_apex("a.b.c.example.com"), "example.com");
}

#[test]
fn extract_apex_single_label_returns_itself() {
    assert_eq!(extract_apex("localhost"), "localhost");
}

#[test]
fn extract_apex_preserves_case() {
    assert_eq!(extract_apex("Sub.Example.COM"), "Example.COM");
}

#[test]
fn extract_apex_compound_tld_co_uk() {
    assert_eq!(extract_apex("sub.example.co.uk"), "example.co.uk");
}

#[test]
fn extract_apex_compound_tld_com_br() {
    assert_eq!(extract_apex("data.corp.com.br"), "corp.com.br");
}

#[test]
fn extract_subdomain_with_compound_tld() {
    assert_eq!(extract_subdomain("sub.example.co.uk"), Some("sub"));
}

#[test]
fn extract_subdomain_returns_none_for_compound_apex() {
    assert_eq!(extract_subdomain("example.co.uk"), None);
}
