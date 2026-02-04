use async_trait::async_trait;
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::net::IpAddr;

/// Result of a DNS resolution with metadata
#[derive(Debug, Clone)]
pub struct DnsResolution {
    pub addresses: Vec<IpAddr>,
    pub cache_hit: bool,
    pub dnssec_status: Option<String>,  // "Secure", "Insecure", "Bogus", "Indeterminate"
    pub cname: Option<String>,  // Canonical name (CNAME record)
}

impl DnsResolution {
    pub fn new(addresses: Vec<IpAddr>, cache_hit: bool) -> Self {
        Self {
            addresses,
            cache_hit,
            dnssec_status: None,
            cname: None,
        }
    }
    
    pub fn with_dnssec(addresses: Vec<IpAddr>, cache_hit: bool, dnssec_status: Option<String>) -> Self {
        Self {
            addresses,
            cache_hit,
            dnssec_status,
            cname: None,
        }
    }
    
    pub fn with_cname(addresses: Vec<IpAddr>, cache_hit: bool, dnssec_status: Option<String>, cname: Option<String>) -> Self {
        Self {
            addresses,
            cache_hit,
            dnssec_status,
            cname,
        }
    }
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError>;
}
