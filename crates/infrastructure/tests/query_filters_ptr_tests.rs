use ferrous_dns_domain::{DnsQuery, RecordType};
use ferrous_dns_infrastructure::dns::resolver::filters::QueryFilters;

fn ptr_query(domain: &str) -> DnsQuery {
    DnsQuery::new(domain, RecordType::PTR)
}

#[test]
fn test_private_ptr_blocked_when_no_local_dns_server() {
    let filters = QueryFilters {
        block_private_ptr: true,
        block_non_fqdn: false,
        local_domain: None,
        has_local_dns_server: false,
    };

    let query = ptr_query("1.10.0.10.in-addr.arpa");
    let result = filters.apply(query);

    assert!(result.is_err(), "Expected FilteredQuery error");
}

#[test]
fn test_private_ptr_allowed_when_local_dns_server_configured() {
    let filters = QueryFilters {
        block_private_ptr: true,
        block_non_fqdn: false,
        local_domain: None,
        has_local_dns_server: true,
    };

    let query = ptr_query("1.10.0.10.in-addr.arpa");
    let result = filters.apply(query);

    assert!(
        result.is_ok(),
        "Expected query to pass through, got {:?}",
        result
    );
}

#[test]
fn test_public_ptr_never_blocked_by_private_filter() {
    let filters = QueryFilters {
        block_private_ptr: true,
        block_non_fqdn: false,
        local_domain: None,
        has_local_dns_server: false,
    };

    let query = ptr_query("8.8.8.8.in-addr.arpa");
    let result = filters.apply(query);

    assert!(
        result.is_ok(),
        "Public PTR should never be blocked by private filter"
    );
}
