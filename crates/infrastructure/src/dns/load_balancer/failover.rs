use super::query::query_server;
use super::strategy::{QueryContext, UpstreamResult};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{debug, warn};

pub struct FailoverStrategy;

impl FailoverStrategy {
    pub fn new() -> Self {
        Self
    }

    pub async fn query_refs(&self, ctx: &QueryContext<'_>) -> Result<UpstreamResult, DomainError> {
        if ctx.servers.is_empty() {
            return Err(DomainError::TransportNoHealthyServers);
        }
        debug!(strategy = "failover", servers = ctx.servers.len(), domain = %ctx.domain, "Trying sequentially");

        for (index, protocol) in ctx.servers.iter().enumerate() {
            match query_server(
                protocol,
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
                    debug!(server = %r.server_addr, latency_ms = r.latency_ms, position = index, "Server responded");
                    return Ok(UpstreamResult {
                        response: r.response,
                        server: r.server_addr,
                        latency_ms: r.latency_ms,
                        pool_name: Arc::clone(ctx.pool_name),
                        server_display: r.server_display,
                    });
                }
                Err(e) => {
                    warn!(protocol = %protocol, error = %e, position = index, "Failing over");
                }
            }
        }
        Err(DomainError::TransportAllServersUnreachable)
    }
}

impl Default for FailoverStrategy {
    fn default() -> Self {
        Self::new()
    }
}
