use async_trait::async_trait;
use ferrous_dns_domain::{DnsQuery, DomainError};
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
        }
    }
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError>;
}
