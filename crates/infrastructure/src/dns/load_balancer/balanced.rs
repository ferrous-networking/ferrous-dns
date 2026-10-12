use super::query::{all_servers_failed, is_servfail, query_server};
use super::strategy::{QueryContext, UpstreamResult};
use ferrous_dns_domain::DomainError;
use std::sync::atomic::{AtomicUsize, Ordering};
use tracing::{debug, warn};

/// Tries each server once, starting from the round-robin position in `next`.
pub(super) async fn query(
    ctx: &QueryContext<'_>,
    next: &AtomicUsize,
) -> Result<UpstreamResult, DomainError> {
    if ctx.servers.is_empty() {
        return Err(DomainError::TransportNoHealthyServers);
    }
    let start_index = next.fetch_add(1, Ordering::Relaxed) % ctx.servers.len();
    debug!(strategy = "balanced", servers = ctx.servers.len(), start_index, domain = %ctx.domain, "Round-robin");

    let mut all_servfail = true;
    for i in 0..ctx.servers.len() {
        let protocol = ctx.servers[(start_index + i) % ctx.servers.len()];
        match query_server(ctx, protocol).await {
            Ok(r) => {
                debug!(server = %r.server_display, latency_ms = r.latency_ms, "Server responded");
                return Ok(r);
            }
            Err(e) => {
                warn!(protocol = %protocol, error = %e, "Server failed, trying next");
                all_servfail &= is_servfail(&e);
            }
        }
    }
    Err(all_servers_failed(all_servfail))
}
