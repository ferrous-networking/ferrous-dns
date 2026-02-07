use super::query::query_server;
use super::strategy::{LoadBalancingStrategy, UpstreamResult};
use async_trait::async_trait;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, warn};

pub struct BalancedStrategy {
    counter: AtomicUsize,
}

impl BalancedStrategy {
    pub fn new() -> Self {
        Self {
            counter: AtomicUsize::new(0),
        }
    }

    fn next_index(&self, server_count: usize) -> usize {
        self.counter.fetch_add(1, Ordering::Relaxed) % server_count
    }
}

impl Default for BalancedStrategy {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LoadBalancingStrategy for BalancedStrategy {
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

        let start_index = self.next_index(servers.len());
        debug!(strategy = "balanced", servers = servers.len(), start_index, domain = %domain, "Round-robin");

        for i in 0..servers.len() {
            let index = (start_index + i) % servers.len();
            let protocol = &servers[index];

            match query_server(protocol, domain, record_type, timeout_ms).await {
                Ok(r) => {
                    debug!(server = %r.server_addr, latency_ms = r.latency_ms, "Server responded");
                    return Ok(UpstreamResult {
                        response: r.response,
                        server: r.server_addr,
                        latency_ms: r.latency_ms,
                    });
                }
                Err(e) => {
                    warn!(protocol = %protocol, error = %e, "Server failed, trying next");
                }
            }
        }

        Err(DomainError::InvalidDomainName(
            "All servers failed in balanced strategy".into(),
        ))
    }

    fn name(&self) -> &'static str {
        "balanced"
    }
}
