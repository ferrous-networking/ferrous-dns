use crate::dns::forwarding::DnsForwarder;
use crate::dns::load_balancer::PoolManager;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::sync::Arc;
use tracing::{debug, info};

pub struct CoreResolver {
    pool_manager: Arc<PoolManager>,
    query_timeout_ms: u64,
    dnssec_enabled: bool,
    local_domain_suffix: Option<(Arc<str>, Arc<str>)>,
    local_dns_server: Option<Arc<str>>,
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

    pub fn with_local_dns_server(mut self, server: Option<String>) -> Self {
        self.local_dns_server = server.map(|s| Arc::from(s.as_str()));
        self
    }

    fn is_local_tld(&self, domain: &str) -> bool {
        let Some((suffix, exact)) = &self.local_domain_suffix else {
            return false;
        };
        domain.eq_ignore_ascii_case(exact.as_ref())
            || (domain.len() > suffix.len()
                && domain[domain.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_ref()))
    }

    async fn resolve_local_tld(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        if let Some(ref server) = self.local_dns_server {
            let forwarder = DnsForwarder::new();
            match forwarder
                .query(
                    server,
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
                        dnssec_status: None,
                        cname_chain: Arc::from(vec![]),
                        upstream_server: Some(server.to_string()),
                        min_ttl: response.min_ttl,
                        authority_records: response.authority_records,
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
                Err(_) => {}
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

        if self.is_local_tld(&query.domain) {
            return self.resolve_local_tld(query).await;
        }

        let result = self
            .pool_manager
            .query(
                &query.domain,
                &query.record_type,
                self.query_timeout_ms,
                self.dnssec_enabled,
            )
            .await?;

        let addresses = Arc::new(result.response.addresses);
        let upstream_server = Some(result.server.to_string());

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
            local_dns: false,
            dnssec_status: None,
            cname_chain: result
                .response
                .cname_chain
                .into_iter()
                .map(|s| Arc::from(s.as_str()))
                .collect::<Arc<[_]>>(),
            upstream_server,
            min_ttl: result.response.min_ttl,
            authority_records: result.response.authority_records,
        })
    }
}
