use crate::dns::forwarding::DnsForwarder;
use crate::dns::load_balancer::{PoolManager, UpstreamRouter};
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, EMPTY_CNAME_CHAIN};
use ferrous_dns_domain::{DnsQuery, DomainError, PrivateIpFilter};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct CoreResolver {
    pool_manager: Arc<PoolManager>,
    query_timeout_ms: u64,
    dnssec_enabled: bool,
    local_domain_suffix: Option<(Arc<str>, Arc<str>)>,
    /// The router's address and its display form, reported as the upstream.
    local_dns_server: Option<(SocketAddr, Arc<str>)>,
}

impl CoreResolver {
    pub fn new(
        pool_manager: Arc<PoolManager>,
        query_timeout_ms: u64,
        dnssec_enabled: bool,
    ) -> Self {
        info!(
            timeout_ms = query_timeout_ms,
            dnssec = dnssec_enabled,
            "Core DNS resolver created"
        );

        Self {
            pool_manager,
            query_timeout_ms,
            dnssec_enabled,
            local_domain_suffix: None,
            local_dns_server: None,
        }
    }

    pub fn with_local_domain(mut self, domain: Option<String>) -> Self {
        self.local_domain_suffix = domain.map(|d| {
            let lower = d.to_lowercase();
            let suffix = format!(".{}", lower);
            (Arc::from(suffix.as_str()), Arc::from(lower.as_str()))
        });
        self
    }

    pub fn with_local_dns_server(mut self, server: Option<SocketAddr>) -> Self {
        self.local_dns_server = server.map(|addr| (addr, Arc::from(addr.to_string())));
        self
    }

    fn is_local_tld(&self, domain: &str) -> bool {
        let Some((suffix, exact)) = &self.local_domain_suffix else {
            return false;
        };
        // Compare bytes: a `str` slice at this offset may split a multi-byte character.
        let domain = domain.as_bytes();
        domain.eq_ignore_ascii_case(exact.as_bytes())
            || (domain.len() > suffix.len()
                && domain[domain.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes()))
    }

    async fn resolve_local_tld(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        if let Some((server, display)) = &self.local_dns_server {
            let forwarder = DnsForwarder::new(self.pool_manager.hardening());
            match forwarder
                .query(
                    *server,
                    &query.domain,
                    &query.record_type,
                    self.query_timeout_ms,
                )
                .await
            {
                Ok(response) if !response.is_nxdomain() && !response.is_server_error() => {
                    debug!(
                        domain = %query.domain,
                        server = %server,
                        "Local TLD query resolved via local DNS server"
                    );
                    return Ok(DnsResolution {
                        addresses: Arc::new(response.addresses),
                        cache_hit: false,
                        local_dns: true,
                        local_nxdomain: false,
                        dnssec_status: None,
                        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
                        upstream_server: Some(Arc::clone(display)),
                        upstream_pool: None,
                        min_ttl: response.min_ttl,
                        negative_soa_ttl: response.negative_soa_ttl,
                        // Relay the full answer, as the pool path does, so non-address
                        // records (PTR, SRV, TXT, MX) reach the client.
                        upstream_wire_data: Some(response.raw_bytes),
                    });
                }
                Ok(_) => {
                    debug!(
                        domain = %query.domain,
                        server = %server,
                        "Local TLD query returned NXDOMAIN from local DNS server"
                    );
                    return Err(DomainError::LocalNxDomain);
                }
                // A router that rewrites the query name's case fails the 0x20
                // check on every answer — surface it rather than a silent NXDOMAIN.
                Err(e) => {
                    warn!(
                        domain = %query.domain,
                        server = %server,
                        error = %e,
                        "Local DNS server query failed"
                    );
                }
            }
        }

        debug!(domain = %query.domain, "Local TLD query not in cache — returning NXDOMAIN");
        Err(DomainError::NxDomain)
    }
}

#[async_trait]
impl DnsResolver for CoreResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        debug!(
            domain = %query.domain,
            record_type = %query.record_type,
            "CoreResolver: performing upstream query"
        );

        let is_local = (self.local_dns_server.is_some()
            && PrivateIpFilter::is_private_ptr_query(&query.domain))
            || self.is_local_tld(&query.domain);
        // A conditional pool is the more specific route: an office's reverse
        // zone, or a domain under `local_domain`, goes to the pool that names it.
        if is_local
            && self
                .pool_manager
                .route(&query.domain, query.group_id)
                .is_none()
        {
            return self.resolve_local_tld(query).await;
        }

        let result = self
            .pool_manager
            .query_for(
                query.group_id,
                &query.domain,
                &query.record_type,
                self.query_timeout_ms,
                self.dnssec_enabled,
            )
            .await?;

        let internal = result.internal;
        let addresses = Arc::new(result.response.addresses);
        let upstream_server = Some(result.server_display);
        let cname_chain = result.response.cname_chain;
        let min_ttl = result.response.min_ttl;
        let negative_soa_ttl = result.response.negative_soa_ttl;
        let raw_bytes = result.response.raw_bytes;

        debug!(
            domain = %query.domain,
            record_type = %query.record_type,
            num_addresses = addresses.len(),
            upstream = upstream_server.as_deref().unwrap_or("unknown"),
            "CoreResolver: query successful"
        );

        Ok(DnsResolution {
            addresses,
            cache_hit: false,
            // An internal pool's answers are trusted like the local DNS
            // server's: no DNSSEC validation, no rebinding protection.
            local_dns: internal,
            local_nxdomain: false,
            dnssec_status: None,
            cname_chain: if cname_chain.is_empty() {
                Arc::clone(&EMPTY_CNAME_CHAIN)
            } else {
                cname_chain.into_iter().collect::<Arc<[_]>>()
            },
            upstream_server,
            upstream_pool: Some(result.pool_name),
            min_ttl,
            negative_soa_ttl,
            upstream_wire_data: Some(raw_bytes),
        })
    }
}
