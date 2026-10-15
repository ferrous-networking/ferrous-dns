use ferrous_dns_domain::{DnsQuery, RecordType};
use ferrous_dns_infrastructure::dns::resolver::filters::{NonFqdn, QueryFilters};
use std::borrow::Cow;

fn qualify(domain: &str) -> NonFqdn {
    NonFqdn::Qualify(domain.to_string())
}

#[test]
fn apply_str_returns_borrowed_for_regular_fqdn() {
    let result = QueryFilters::new(false, NonFqdn::Pass).apply_str("google.com", None);
    assert!(result.is_some());
    let cow = result.unwrap();
    assert_eq!(cow.as_ref(), "google.com");
    assert!(
        matches!(cow, Cow::Borrowed(_)),
        "must not allocate for unmodified FQDN"
    );
}

#[test]
fn apply_str_returns_none_for_private_ptr_when_blocked() {
    let filters = QueryFilters::new(true, NonFqdn::Pass);
    assert!(filters.apply_str("1.10.0.10.in-addr.arpa", None).is_none());
}

#[test]
fn apply_str_never_blocks_public_ptr() {
    let filters = QueryFilters::new(true, NonFqdn::Pass);
    assert!(filters.apply_str("8.8.8.8.in-addr.arpa", None).is_some());
}

#[test]
fn apply_str_returns_none_for_single_label_when_block_non_fqdn() {
    let filters = QueryFilters::new(false, NonFqdn::Block);
    assert!(filters.apply_str("printer", None).is_none());
}

#[test]
fn apply_str_allows_fqdn_when_block_non_fqdn_enabled() {
    let filters = QueryFilters::new(false, NonFqdn::Block);
    let result = filters.apply_str("printer.local", None);
    assert!(result.is_some());
    assert!(matches!(result.unwrap(), Cow::Borrowed(_)));
}

#[test]
fn apply_str_appends_local_domain_to_single_label_and_returns_owned() {
    let filters = QueryFilters::new(false, qualify("lan"));
    let result = filters.apply_str("printer", None);
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
    let filters = QueryFilters::new(false, qualify("lan"));
    let result = filters.apply_str("google.com", None);
    assert!(result.is_some());
    let cow = result.unwrap();
    assert_eq!(cow.as_ref(), "google.com");
    assert!(
        matches!(cow, Cow::Borrowed(_)),
        "must not allocate for FQDN with local_domain configured"
    );
}

#[test]
fn apply_qualifies_single_label_query_with_local_domain() {
    let filters = QueryFilters::new(false, qualify("home"));
    let query = filters.apply(DnsQuery::new("nas", RecordType::A)).unwrap();
    assert_eq!(query.domain.as_ref(), "nas.home");
}
