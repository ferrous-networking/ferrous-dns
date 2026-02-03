use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, warn};

use super::cache::DnsCache;

pub struct HickoryDnsResolver {
    resolver: Resolver<TokioConnectionProvider>,
    cache: Option<Arc<DnsCache>>,
    cache_ttl: u64, // TTL in seconds for cached entries
}

impl HickoryDnsResolver {
    /// Create resolver with system configuration
    pub fn new() -> Result<Self, DomainError> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self {
            resolver,
            cache: None,
            cache_ttl: 3600, // Default 1 hour
        })
    }

    /// Create resolver with Google DNS (8.8.8.8)
    pub fn with_google() -> Result<Self, DomainError> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::google(),
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self {
            resolver,
            cache: None,
            cache_ttl: 3600, // Default 1 hour
        })
    }

    /// Create resolver with Cloudflare DNS (1.1.1.1)
    pub fn with_cloudflare() -> Result<Self, DomainError> {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::cloudflare(),
            TokioConnectionProvider::default(),
        )
        .build();

        Ok(Self {
            resolver,
            cache: None,
            cache_ttl: 3600, // Default 1 hour
        })
    }

    /// Enable caching for this resolver
    pub fn with_cache(mut self, cache: Arc<DnsCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Set cache TTL (must be called after with_cache)
    pub fn with_cache_ttl(mut self, ttl: u64) -> Self {
        self.cache_ttl = ttl;
        self
    }
}

#[async_trait]
impl DnsResolver for HickoryDnsResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // Check cache first
        if let Some(cache) = &self.cache {
            if let Some(addresses) = cache.get(&query.domain, &query.record_type).await {
                debug!(
                    domain = %query.domain,
                    record_type = %query.record_type,
                    "Cache hit"
                );
                return Ok(DnsResolution::new(addresses, true)); // ✅ Cache hit!
            }
        }

        // Cache miss - resolve upstream
        let addresses = self.resolve_upstream(query).await?;

        // Store in cache (only for cacheable record types)
        if let Some(cache) = &self.cache {
            if !addresses.is_empty() && Self::is_cacheable(&query.record_type) {
                cache.insert(
                    &query.domain,
                    &query.record_type,
                    addresses.clone(),
                    self.cache_ttl,
                );
                debug!(
                    domain = %query.domain,
                    record_type = %query.record_type,
                    ttl = self.cache_ttl,
                    "Cached DNS response"
                );
            }
        }

        Ok(DnsResolution::new(addresses, false)) // ✅ Not from cache
    }
}

impl HickoryDnsResolver {
    /// Check if record type should be cached
    fn is_cacheable(record_type: &RecordType) -> bool {
        match record_type {
            // ✅ Cacheable - IP resolution records
            RecordType::A | RecordType::AAAA | RecordType::CNAME => true,

            // ✅ Cacheable - Email records
            RecordType::MX => true,

            // ✅ Cacheable - Name server records
            RecordType::NS => true,

            // ✅ Cacheable - Text records (SPF, DKIM, etc.)
            RecordType::TXT => true,

            // ✅ Cacheable - Service records
            RecordType::SRV => true,

            // ✅ Cacheable - Modern records
            RecordType::SVCB | RecordType::HTTPS => true,

            // ✅ Cacheable - Security records
            RecordType::CAA | RecordType::TLSA | RecordType::SSHFP => true,

            // ❌ Not cacheable - Dynamic/administrative records
            RecordType::SOA | RecordType::PTR | RecordType::NAPTR | RecordType::DNAME => false,

            // ❌ Not cacheable - DNSSEC records (frequently change)
            RecordType::DS
            | RecordType::DNSKEY
            | RecordType::RRSIG
            | RecordType::NSEC
            | RecordType::NSEC3
            | RecordType::NSEC3PARAM
            | RecordType::CDS
            | RecordType::CDNSKEY => false,
        }
    }

    /// Resolve from upstream DNS without cache
    async fn resolve_upstream(&self, query: &DnsQuery) -> Result<Vec<IpAddr>, DomainError> {
        use hickory_proto::rr::RecordType as HickoryRecordType;

        match query.record_type {
            RecordType::A => {
                self.resolve_ip_records(
                    &query.domain,
                    "A",
                    self.resolver.ipv4_lookup(&query.domain),
                    |r| IpAddr::V4(r.0),
                )
                .await
            }
            RecordType::AAAA => {
                self.resolve_ip_records(
                    &query.domain,
                    "AAAA",
                    self.resolver.ipv6_lookup(&query.domain),
                    |r| IpAddr::V6(r.0),
                )
                .await
            }
            RecordType::MX => {
                self.resolve_non_ip_records(&query.domain, "MX", HickoryRecordType::MX)
                    .await
            }
            RecordType::TXT => {
                self.resolve_non_ip_records(&query.domain, "TXT", HickoryRecordType::TXT)
                    .await
            }
            RecordType::CNAME => {
                self.resolve_non_ip_records(&query.domain, "CNAME", HickoryRecordType::CNAME)
                    .await
            }
            RecordType::PTR => {
                self.resolve_non_ip_records(&query.domain, "PTR", HickoryRecordType::PTR)
                    .await
            }
            RecordType::SRV => {
                self.resolve_non_ip_records(&query.domain, "SRV", HickoryRecordType::SRV)
                    .await
            }
            RecordType::SOA => {
                self.resolve_non_ip_records(&query.domain, "SOA", HickoryRecordType::SOA)
                    .await
            }
            RecordType::NS => {
                self.resolve_non_ip_records(&query.domain, "NS", HickoryRecordType::NS)
                    .await
            }
            RecordType::NAPTR => {
                self.resolve_non_ip_records(&query.domain, "NAPTR", HickoryRecordType::NAPTR)
                    .await
            }
            RecordType::DS => {
                self.resolve_non_ip_records(&query.domain, "DS", HickoryRecordType::DS)
                    .await
            }
            RecordType::DNSKEY => {
                self.resolve_non_ip_records(&query.domain, "DNSKEY", HickoryRecordType::DNSKEY)
                    .await
            }
            RecordType::SVCB => {
                self.resolve_non_ip_records(&query.domain, "SVCB", HickoryRecordType::SVCB)
                    .await
            }
            RecordType::HTTPS => {
                self.resolve_non_ip_records(&query.domain, "HTTPS", HickoryRecordType::HTTPS)
                    .await
            }
            RecordType::CAA => {
                self.resolve_non_ip_records(&query.domain, "CAA", HickoryRecordType::CAA)
                    .await
            }
            RecordType::TLSA => {
                self.resolve_non_ip_records(&query.domain, "TLSA", HickoryRecordType::TLSA)
                    .await
            }
            RecordType::SSHFP => {
                self.resolve_non_ip_records(&query.domain, "SSHFP", HickoryRecordType::SSHFP)
                    .await
            }
            RecordType::DNAME => {
                debug!(domain = %query.domain, "DNAME not supported in Hickory 0.25");
                Ok(vec![])
            }
            RecordType::RRSIG => {
                self.resolve_non_ip_records(&query.domain, "RRSIG", HickoryRecordType::RRSIG)
                    .await
            }
            RecordType::NSEC => {
                self.resolve_non_ip_records(&query.domain, "NSEC", HickoryRecordType::NSEC)
                    .await
            }
            RecordType::NSEC3 => {
                self.resolve_non_ip_records(&query.domain, "NSEC3", HickoryRecordType::NSEC3)
                    .await
            }
            RecordType::NSEC3PARAM => {
                self.resolve_non_ip_records(
                    &query.domain,
                    "NSEC3PARAM",
                    HickoryRecordType::NSEC3PARAM,
                )
                .await
            }
            RecordType::CDS => {
                self.resolve_non_ip_records(&query.domain, "CDS", HickoryRecordType::CDS)
                    .await
            }
            RecordType::CDNSKEY => {
                self.resolve_non_ip_records(&query.domain, "CDNSKEY", HickoryRecordType::CDNSKEY)
                    .await
            }
        }
    }

    async fn resolve_ip_records<Fut, Resp, Item, Map>(
        &self,
        domain: &str,
        record_name: &'static str,
        fut: Fut,
        map: Map,
    ) -> Result<Vec<IpAddr>, DomainError>
    where
        Fut: std::future::Future<Output = Result<Resp, hickory_resolver::ResolveError>>,
        Resp: IntoIterator<Item = Item>,
        Map: Fn(Item) -> IpAddr,
    {
        match fut.await {
            Ok(response) => {
                let ips: Vec<IpAddr> = response.into_iter().map(map).collect();
                debug!(domain = %domain, count = ips.len(), "{record_name} records resolved");
                Ok(ips)
            }
            Err(e) => handle_no_records_error(domain, record_name, e),
        }
    }

    async fn resolve_non_ip_records(
        &self,
        domain: &str,
        record_name: &'static str,
        record_type: hickory_proto::rr::RecordType,
    ) -> Result<Vec<IpAddr>, DomainError> {
        match self.resolver.lookup(domain, record_type).await {
            Ok(lookup) => {
                let count = lookup.record_iter().count();
                if count > 0 {
                    debug!(domain = %domain, count, "{record_name} records found");
                } else {
                    debug!(domain = %domain, "No {record_name} records found");
                }
                Ok(vec![])
            }
            Err(e) => handle_no_records_error(domain, record_name, e),
        }
    }
}

fn handle_no_records_error(
    domain: &str,
    record_type: &str,
    e: impl std::fmt::Display,
) -> Result<Vec<IpAddr>, DomainError> {
    let error_msg = e.to_string();
    if error_msg.contains("no records found")
        || error_msg.contains("no records")
        || error_msg.contains("NoRecordsFound")
    {
        debug!(domain = %domain, "No {} records found", record_type);
        Ok(vec![])
    } else {
        warn!(domain = %domain, error = %e, "{} lookup failed", record_type);
        Err(DomainError::InvalidDomainName(e.to_string()))
    }
}
