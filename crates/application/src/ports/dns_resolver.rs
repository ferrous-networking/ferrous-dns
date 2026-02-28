use async_trait::async_trait;
use bytes::Bytes;
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

pub static EMPTY_CNAME_CHAIN: LazyLock<Arc<[Arc<str>]>> = LazyLock::new(|| Arc::from([]));

#[derive(Debug, Clone)]
pub struct DnsResolution {
    pub addresses: Arc<Vec<IpAddr>>,
    pub cache_hit: bool,
    pub local_dns: bool,
    pub dnssec_status: Option<&'static str>,
    pub cname_chain: Arc<[Arc<str>]>,
    pub upstream_server: Option<Arc<str>>,
    pub upstream_pool: Option<Arc<str>>,
    pub min_ttl: Option<u32>,
    /// SOA minimum TTL extracted from upstream authority records.
    /// Used by cache layer to set TTL for negative responses.
    pub negative_soa_ttl: Option<u32>,
    /// Wire bytes of the complete upstream DNS response.
    /// Opaque to the application layer — consumed by infrastructure
    /// (DNS server handler, DNSSEC validator).
    pub upstream_wire_data: Option<Bytes>,
}

impl DnsResolution {
    pub fn new(addresses: Vec<IpAddr>, cache_hit: bool) -> Self {
        Self {
            addresses: Arc::new(addresses),
            cache_hit,
            local_dns: false,
            dnssec_status: None,
            cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
            upstream_server: None,
            upstream_pool: None,
            min_ttl: None,
            negative_soa_ttl: None,
            upstream_wire_data: None,
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
            local_dns: false,
            dnssec_status,
            cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
            upstream_server: None,
            upstream_pool: None,
            min_ttl: None,
            negative_soa_ttl: None,
            upstream_wire_data: None,
        }
    }
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError>;

    fn try_cache(&self, _query: &DnsQuery) -> Option<DnsResolution> {
        None
    }
}
