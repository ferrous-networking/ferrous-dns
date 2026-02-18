use super::query::query_server;
use super::strategy::UpstreamResult;
use crate::dns::events::QueryEventEmitter;
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

    pub async fn query_refs(
        &self,
        servers: &[&DnsProtocol],
        domain: &str,
        record_type: &RecordType,
        timeout_ms: u64,
        emitter: &QueryEventEmitter,
    ) -> Result<UpstreamResult, DomainError> {
        if servers.is_empty() {
            return Err(DomainError::InvalidDomainName(
                "No upstream servers available".into(),
            ));
        }
        let start_index = self.counter.fetch_add(1, Ordering::Relaxed) % servers.len();
        debug!(strategy = "balanced", servers = servers.len(), start_index, domain = %domain, "Round-robin");

        for i in 0..servers.len() {
            let index = (start_index + i) % servers.len();
            match query_server(servers[index], domain, record_type, timeout_ms, emitter).await {
                Ok(r) => {
                    debug!(server = %r.server_addr, latency_ms = r.latency_ms, "Server responded");
                    return Ok(UpstreamResult {
                        response: r.response,
                        server: r.server_addr,
                        latency_ms: r.latency_ms,
                    });
                }
                Err(e) => {
                    warn!(protocol = %servers[index], error = %e, "Server failed, trying next");
                }
            }
        }
        Err(DomainError::InvalidDomainName(
            "All servers failed in balanced strategy".into(),
        ))
    }
}

impl Default for BalancedStrategy {
    fn default() -> Self {
        Self::new()
    }
}
