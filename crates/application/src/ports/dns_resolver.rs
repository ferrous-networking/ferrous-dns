use async_trait::async_trait;
use ferrous_dns_domain::{DnsQuery, DomainError};
use hickory_proto::rr::Record;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DnsResolution {
    pub addresses: Arc<Vec<IpAddr>>,
    pub cache_hit: bool,
    pub dnssec_status: Option<&'static str>,
    pub cname: Option<String>,
    pub upstream_server: Option<String>,
    pub min_ttl: Option<u32>,
    /// Records from the AUTHORITY section of the upstream response (e.g. SOA for NODATA).
    pub authority_records: Vec<Record>,
}

impl DnsResolution {
    pub fn new(addresses: Vec<IpAddr>, cache_hit: bool) -> Self {
        Self {
            addresses: Arc::new(addresses),
            cache_hit,
            dnssec_status: None,
            cname: None,
            upstream_server: None,
            min_ttl: None,
            authority_records: vec![],
        }
    }

    pub fn with_dnssec(
        addresses: Vec<IpAddr>,
        cache_hit: bool,
        dnssec_status: Option<&'static str>,
    ) -> Self {
        Self {
            addresses: Arc::new(addresses),
            cache_hit,
            dnssec_status,
            cname: None,
            upstream_server: None,
            min_ttl: None,
            authority_records: vec![],
        }
    }

    pub fn with_cname(
        addresses: Vec<IpAddr>,
        cache_hit: bool,
        dnssec_status: Option<&'static str>,
        cname: Option<String>,
    ) -> Self {
        Self {
            addresses: Arc::new(addresses),
            cache_hit,
            dnssec_status,
            cname,
            upstream_server: None,
            min_ttl: None,
            authority_records: vec![],
        }
    }
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError>;

    /// Check only the DNS cache without going to upstream.
    /// Returns `Some(resolution)` on hit, `None` on miss.
    /// Default implementation returns None (no cache).
    fn try_cache(&self, _query: &DnsQuery) -> Option<DnsResolution> {
        None
    }
}
