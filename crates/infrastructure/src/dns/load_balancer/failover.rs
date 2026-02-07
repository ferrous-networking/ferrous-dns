use super::query::query_server;
use super::strategy::{LoadBalancingStrategy, UpstreamResult};
use async_trait::async_trait;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use tracing::{debug, warn};

pub struct FailoverStrategy;

impl FailoverStrategy {
    pub fn new() -> Self {
        Self
    }
}

impl Default for FailoverStrategy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LoadBalancingStrategy for FailoverStrategy {
    async fn query(
        &self,
        servers: &[DnsProtocol],
        domain: &str,
        record_type: &RecordType,
        timeout_ms: u64,
    ) -> Result<UpstreamResult, DomainError> {
        if servers.is_empty() {
            return Err(DomainError::InvalidDomainName(
                "No upstream servers available".into(),
            ));
        }

        debug!(strategy = "failover", servers = servers.len(), domain = %domain, "Trying sequentially");

        for (index, protocol) in servers.iter().enumerate() {
            match query_server(protocol, domain, record_type, timeout_ms).await {
                Ok(r) => {
                    debug!(server = %r.server_addr, latency_ms = r.latency_ms, position = index, "Server responded");
                    return Ok(UpstreamResult {
                        response: r.response,
                        server: r.server_addr,
                        latency_ms: r.latency_ms,
                    });
                }
                Err(e) => {
                    warn!(protocol = %protocol, error = %e, position = index, "Failing over");
                }
            }
        }

        Err(DomainError::InvalidDomainName(
            "All servers failed in failover strategy".into(),
        ))
    }

    fn name(&self) -> &'static str {
        "failover"
    }
}
