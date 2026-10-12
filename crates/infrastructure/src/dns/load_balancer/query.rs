use super::strategy::{QueryContext, ServerDisplays, UpstreamResult};
use crate::dns::forwarding::forwarder::exchange_with_tc_retry;
use crate::dns::forwarding::ResponseParser;
use ferrous_dns_domain::{DnsProtocol, DomainError};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn get_display(protocol: &DnsProtocol, cache: &ServerDisplays) -> Arc<str> {
    cache
        .get(protocol)
        .map(Arc::clone)
        .unwrap_or_else(|| Arc::from(protocol.to_string()))
}

/// Whether `error` is an upstream answering SERVFAIL: one server, or every
/// server a strategy asked.
pub(super) fn is_servfail(error: &DomainError) -> bool {
    match error {
        DomainError::UpstreamServerFailure { rcode, .. } => *rcode == "SERVFAIL",
        DomainError::AllUpstreamsServfail => true,
        _ => false,
    }
}

/// The error for a strategy whose every server failed: SERVFAIL only when
/// each one answered it, so a timeout next to a SERVFAIL is not reported as
/// an upstream that declined.
pub(super) fn all_servers_failed(all_servfail: bool) -> DomainError {
    if all_servfail {
        DomainError::AllUpstreamsServfail
    } else {
        DomainError::TransportAllServersUnreachable
    }
}

/// One attempt against `protocol` within the pool query described by `ctx`.
///
/// A reply that declines the question (SERVFAIL, REFUSED, ...) is an error, so
/// every strategy moves on to its next server instead of returning it, and
/// nothing downstream caches it or renews an entry with it.
pub(super) async fn query_server(
    ctx: &QueryContext<'_>,
    protocol: &DnsProtocol,
) -> Result<UpstreamResult, DomainError> {
    let start = Instant::now();
    let (response, tcp_retry) = exchange_with_tc_retry(
        protocol,
        ctx.query_bytes,
        ctx.validator,
        Duration::from_millis(ctx.timeout_ms),
    )
    .await?;

    let display = get_display(protocol, ctx.server_displays);
    if !response.is_answer() {
        return Err(DomainError::UpstreamServerFailure {
            server: display.to_string(),
            rcode: ResponseParser::rcode_to_status(response.rcode),
        });
    }
    Ok(UpstreamResult {
        response,
        latency_ms: start.elapsed().as_millis() as u64,
        pool_name: Arc::clone(ctx.pool_name),
        // Keeps the configured name: the TCP retry reaches the same server.
        server_display: if tcp_retry {
            Arc::from(format!("{display} (tcp retry)"))
        } else {
            display
        },
    })
}
