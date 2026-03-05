use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, PtrRecordRegistry};
use ferrous_dns_domain::{DnsQuery, DomainError, LocalDnsRecord, RecordType};
use ferrous_dns_infrastructure::dns::resolver::LocalPtrResolver;
use std::net::IpAddr;
use std::sync::Arc;

struct MockInner;

#[async_trait]
impl DnsResolver for MockInner {
    async fn resolve(&self, _query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        Err(DomainError::NxDomain)
    }
}

fn make_record(hostname: &str, domain: &str, ip: &str, record_type: &str) -> LocalDnsRecord {
    LocalDnsRecord {
        hostname: hostname.to_string(),
        domain: Some(domain.to_string()),
        ip: ip.to_string(),
        record_type: record_type.to_string(),
        ttl: Some(300),
    }
}

fn ptr_query(reverse_name: &str) -> DnsQuery {
    DnsQuery::new(reverse_name, RecordType::PTR)
}

fn a_query(domain: &str) -> DnsQuery {
    DnsQuery::new(domain, RecordType::A)
}

#[tokio::test]
async fn test_ptr_query_for_local_record_returns_wire_data() {
    let records = vec![make_record("server", "local", "10.0.10.1", "A")];
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver =
        LocalPtrResolver::from_local_records(&records, &Some("local".to_string()), inner);

    let query = ptr_query("1.10.0.10.in-addr.arpa");
    let result = resolver.resolve(&query).await;

    assert!(result.is_ok(), "Expected Ok, got {:?}", result);
    let resolution = result.unwrap();
    assert!(
        resolution.upstream_wire_data.is_some(),
        "Expected wire data for PTR hit"
    );
    assert!(resolution.local_dns);
    assert_eq!(resolution.min_ttl, Some(300));
}

#[tokio::test]
async fn test_ptr_query_unknown_ip_passes_through() {
    let records = vec![make_record("server", "local", "10.0.10.1", "A")];
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver =
        LocalPtrResolver::from_local_records(&records, &Some("local".to_string()), inner);

    let query = ptr_query("99.10.0.10.in-addr.arpa");
    let result = resolver.resolve(&query).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
}

#[tokio::test]
async fn test_a_query_passes_through_without_touching_map() {
    let records = vec![make_record("server", "local", "10.0.10.1", "A")];
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver =
        LocalPtrResolver::from_local_records(&records, &Some("local".to_string()), inner);

    let query = a_query("server.local");
    let result = resolver.resolve(&query).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
}

#[tokio::test]
async fn test_from_local_records_preloads_all_valid_entries() {
    let records = vec![
        make_record("host1", "local", "10.0.0.1", "A"),
        make_record("host2", "local", "10.0.0.2", "A"),
        make_record("host3", "local", "10.0.0.3", "A"),
    ];
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver =
        LocalPtrResolver::from_local_records(&records, &Some("local".to_string()), inner);

    assert_eq!(resolver.map.len(), 3);
}

#[tokio::test]
async fn test_from_local_records_skips_invalid_ip() {
    let records = vec![
        make_record("good", "local", "10.0.0.1", "A"),
        make_record("bad", "local", "not-an-ip", "A"),
    ];
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver =
        LocalPtrResolver::from_local_records(&records, &Some("local".to_string()), inner);

    assert_eq!(resolver.map.len(), 1);
}

#[tokio::test]
async fn test_register_adds_entry_to_map() {
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver = LocalPtrResolver::from_local_records(&[], &None, inner);

    let ip: IpAddr = "10.0.0.5".parse().unwrap();
    resolver.register(ip, Arc::from("nas.local"), 300);

    let query = ptr_query("5.0.0.10.in-addr.arpa");
    let result = resolver.resolve(&query).await;

    assert!(result.is_ok());
    assert!(result.unwrap().upstream_wire_data.is_some());
}

#[tokio::test]
async fn test_unregister_removes_entry_from_map() {
    let records = vec![make_record("server", "local", "10.0.10.1", "A")];
    let inner: Arc<dyn DnsResolver> = Arc::new(MockInner);
    let resolver =
        LocalPtrResolver::from_local_records(&records, &Some("local".to_string()), inner);

    let ip: IpAddr = "10.0.10.1".parse().unwrap();
    resolver.unregister(ip);

    let query = ptr_query("1.10.0.10.in-addr.arpa");
    let result = resolver.resolve(&query).await;

    assert!(matches!(result, Err(DomainError::NxDomain)));
}
