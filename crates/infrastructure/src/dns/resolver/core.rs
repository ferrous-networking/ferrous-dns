use crate::dns::conditional_forwarder::ConditionalForwarder;
use crate::dns::load_balancer::PoolManager;
use async_trait::async_trait;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::sync::Arc;
use tracing::{debug, info};

pub struct CoreResolver {
    pool_manager: Arc<PoolManager>,
    query_timeout_ms: u64,
    conditional_forwarder: Option<Arc<ConditionalForwarder>>,
}

impl CoreResolver {
    pub fn new(pool_manager: Arc<PoolManager>, query_timeout_ms: u64) -> Self {
        info!(timeout_ms = query_timeout_ms, "Core DNS resolver created");

        Self {
            pool_manager,
            query_timeout_ms,
            conditional_forwarder: None,
        }
    }

    pub fn with_conditional_forwarder(mut self, forwarder: Arc<ConditionalForwarder>) -> Self {
        self.conditional_forwarder = Some(forwarder);
        self
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

        if let Some(ref forwarder) = self.conditional_forwarder {
            if let Some((rule, server)) = forwarder.should_forward(query) {
                debug!(
                    domain = %query.domain,
                    record_type = %query.record_type,
                    rule_domain = %rule.domain,
                    server = %server,
                    "Using conditional forwarding"
                );

                match forwarder
                    .query_specific_server(query, &server, self.query_timeout_ms)
                    .await
                {
                    Ok(addresses) => {
                        debug!(
                            domain = %query.domain,
                            addresses = addresses.len(),
                            server = %server,
                            "Conditional forwarding successful"
                        );

                        return Ok(DnsResolution {
                            addresses: Arc::new(addresses),
                            cache_hit: false,
                            dnssec_status: None,
                            cname: None,
                            upstream_server: Some(format!("conditional:{}", server)),
                            min_ttl: None,
                        });
                    }
                    Err(e) => {
                        debug!(
                            error = %e,
                            domain = %query.domain,
                            server = %server,
                            "Conditional forwarding failed, falling back to upstream"
                        );
                    }
                }
            }
        }

        let result = self
            .pool_manager
            .query(&query.domain, &query.record_type, self.query_timeout_ms)
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
            dnssec_status: None,
            cname: None,
            upstream_server,
            min_ttl: result.response.min_ttl,
        })
    }
}
