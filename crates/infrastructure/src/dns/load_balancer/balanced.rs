use super::query::query_server;
use super::strategy::{QueryContext, UpstreamResult};
use ferrous_dns_domain::DomainError;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
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

    pub async fn query_refs(&self, ctx: &QueryContext<'_>) -> Result<UpstreamResult, DomainError> {
        if ctx.servers.is_empty() {
            return Err(DomainError::TransportNoHealthyServers);
        }
        let start_index = self.counter.fetch_add(1, Ordering::Relaxed) % ctx.servers.len();
        debug!(strategy = "balanced", servers = ctx.servers.len(), start_index, domain = %ctx.domain, "Round-robin");

        for i in 0..ctx.servers.len() {
            let index = (start_index + i) % ctx.servers.len();
            match query_server(
                ctx.servers[index],
                ctx.domain,
                ctx.record_type,
                ctx.timeout_ms,
                ctx.dnssec_ok,
                ctx.emitter,
                ctx.pool_name,
            )
            .await
            {
                Ok(r) => {
                    debug!(server = %r.server_addr, latency_ms = r.latency_ms, "Server responded");
                    return Ok(UpstreamResult {
                        response: r.response,
                        server: r.server_addr,
                        latency_ms: r.latency_ms,
                        pool_name: Arc::clone(ctx.pool_name),
                        server_display: r.server_display,
                    });
                }
                Err(e) => {
                    warn!(protocol = %ctx.servers[index], error = %e, "Server failed, trying next");
                }
            }
        }
        Err(DomainError::TransportAllServersUnreachable)
    }
}

impl Default for BalancedStrategy {
    fn default() -> Self {
        Self::new()
    }
}
