use ferrous_dns_domain::{BlockSource, DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::resolver::filters::{NonFqdn, QueryFilters};

fn ptr_query(domain: &str) -> DnsQuery {
    DnsQuery::new(domain, RecordType::PTR)
}

#[test]
fn test_private_ptr_blocked_when_filter_enabled() {
    let filters = QueryFilters::new(true, NonFqdn::Pass);

    let query = ptr_query("1.10.0.10.in-addr.arpa");
    let result = filters.apply(query);

    assert!(
        matches!(
            result,
            Err(DomainError::FilteredQuery(BlockSource::PrivatePtr))
        ),
        "Expected a PrivatePtr FilteredQuery, got {result:?}"
    );
}

#[test]
fn test_public_ptr_never_blocked_by_private_filter() {
    let filters = QueryFilters::new(true, NonFqdn::Pass);

    let query = ptr_query("8.8.8.8.in-addr.arpa");
    let result = filters.apply(query);

    assert!(
        result.is_ok(),
        "Public PTR should never be blocked by private filter"
    );
}
