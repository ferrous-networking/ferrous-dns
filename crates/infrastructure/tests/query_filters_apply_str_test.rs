use ferrous_dns_infrastructure::dns::resolver::filters::QueryFilters;
use std::borrow::Cow;

fn filters_passthrough() -> QueryFilters {
    QueryFilters {
        block_private_ptr: false,
        block_non_fqdn: false,
        local_domain: None,
        has_local_dns_server: false,
    }
}

// ── no-op path ───────────────────────────────────────────────────────────────

#[test]
fn apply_str_returns_borrowed_for_regular_fqdn() {
    let result = filters_passthrough().apply_str("google.com");
    assert!(result.is_some());
    let cow = result.unwrap();
    assert_eq!(cow.as_ref(), "google.com");
    assert!(
        matches!(cow, Cow::Borrowed(_)),
        "must not allocate for unmodified FQDN"
    );
}

// ── private PTR filter ───────────────────────────────────────────────────────

#[test]
fn apply_str_returns_none_for_private_ptr_when_no_local_dns_server() {
    let filters = QueryFilters {
        block_private_ptr: true,
        block_non_fqdn: false,
        local_domain: None,
        has_local_dns_server: false,
    };
    assert!(filters.apply_str("1.10.0.10.in-addr.arpa").is_none());
}

#[test]
fn apply_str_allows_private_ptr_when_local_dns_server_configured() {
    let filters = QueryFilters {
        block_private_ptr: true,
        block_non_fqdn: false,
        local_domain: None,
        has_local_dns_server: true,
    };
    let result = filters.apply_str("1.10.0.10.in-addr.arpa");
    assert!(result.is_some());
    assert!(matches!(result.unwrap(), Cow::Borrowed(_)));
}

#[test]
fn apply_str_never_blocks_public_ptr() {
    let filters = QueryFilters {
        block_private_ptr: true,
        block_non_fqdn: false,
        local_domain: None,
        has_local_dns_server: false,
    };
    assert!(filters.apply_str("8.8.8.8.in-addr.arpa").is_some());
}

// ── block_non_fqdn ───────────────────────────────────────────────────────────

#[test]
fn apply_str_returns_none_for_single_label_when_block_non_fqdn() {
    let filters = QueryFilters {
        block_private_ptr: false,
        block_non_fqdn: true,
        local_domain: None,
        has_local_dns_server: false,
    };
    assert!(filters.apply_str("printer").is_none());
}

#[test]
fn apply_str_allows_fqdn_when_block_non_fqdn_enabled() {
    let filters = QueryFilters {
        block_private_ptr: false,
        block_non_fqdn: true,
        local_domain: None,
        has_local_dns_server: false,
    };
    let result = filters.apply_str("printer.local");
    assert!(result.is_some());
    assert!(matches!(result.unwrap(), Cow::Borrowed(_)));
}

// ── local domain append ──────────────────────────────────────────────────────

#[test]
fn apply_str_appends_local_domain_to_single_label_and_returns_owned() {
    let filters = QueryFilters {
        block_private_ptr: false,
        block_non_fqdn: false,
        local_domain: Some("lan".to_string()),
        has_local_dns_server: false,
    };
    let result = filters.apply_str("printer");
    assert!(result.is_some());
    let cow = result.unwrap();
    assert_eq!(cow.as_ref(), "printer.lan");
    assert!(
        matches!(cow, Cow::Owned(_)),
        "must allocate when appending local domain"
    );
}

#[test]
fn apply_str_returns_borrowed_for_fqdn_even_when_local_domain_configured() {
    let filters = QueryFilters {
        block_private_ptr: false,
        block_non_fqdn: false,
        local_domain: Some("lan".to_string()),
        has_local_dns_server: false,
    };
    let result = filters.apply_str("google.com");
    assert!(result.is_some());
    let cow = result.unwrap();
    assert_eq!(cow.as_ref(), "google.com");
    assert!(
        matches!(cow, Cow::Borrowed(_)),
        "must not allocate for FQDN with local_domain configured"
    );
}

// ── parity with apply() ──────────────────────────────────────────────────────

#[test]
fn apply_str_and_apply_agree_on_private_ptr_block() {
    use ferrous_dns_domain::{DnsQuery, RecordType};

    let filters = QueryFilters {
        block_private_ptr: true,
        block_non_fqdn: false,
        local_domain: None,
        has_local_dns_server: false,
    };
    let domain = "1.168.192.in-addr.arpa";
    let query = DnsQuery::new(domain, RecordType::PTR);

    let via_apply = filters.apply(query).is_err();
    let via_apply_str = filters.apply_str(domain).is_none();
    assert_eq!(
        via_apply, via_apply_str,
        "apply and apply_str must agree on filtering decision"
    );
}

#[test]
fn apply_str_and_apply_agree_on_local_domain_append() {
    use ferrous_dns_domain::{DnsQuery, RecordType};

    let filters = QueryFilters {
        block_private_ptr: false,
        block_non_fqdn: false,
        local_domain: Some("home".to_string()),
        has_local_dns_server: false,
    };
    let domain = "nas";
    let query = DnsQuery::new(domain, RecordType::A);

    let via_apply = filters.apply(query).unwrap().domain.as_ref().to_string();
    let via_apply_str = filters.apply_str(domain).unwrap().into_owned();
    assert_eq!(via_apply, via_apply_str);
}
