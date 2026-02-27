use super::query::query_server;
use super::strategy::{QueryContext, UpstreamResult};
use ferrous_dns_domain::DomainError;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::debug;

pub struct ParallelStrategy;

impl ParallelStrategy {
    pub fn new() -> Self {
        Self
    }

    pub async fn query_refs(&self, ctx: &QueryContext<'_>) -> Result<UpstreamResult, DomainError> {
        if ctx.servers.is_empty() {
            return Err(DomainError::TransportNoHealthyServers);
        }

        debug!(
            strategy = "parallel",
            servers = ctx.servers.len(),
            domain = %ctx.domain,
            "Racing all upstreams with immediate cancellation"
        );

        let mut futs = FuturesUnordered::new();

        let per_server_timeout_ms = ctx.timeout_ms.saturating_mul(2);

        let domain_arc: Arc<str> = ctx.domain.into();
        for &protocol in ctx.servers {
            let protocol = protocol.clone();
            let domain = Arc::clone(&domain_arc);
            let record_type = *ctx.record_type;
            let emitter = ctx.emitter.clone();
            let pool_name = Arc::clone(ctx.pool_name);

            futs.push(async move {
                query_server(
                    &protocol,
                    &domain,
                    &record_type,
                    per_server_timeout_ms,
                    ctx.dnssec_ok,
                    &emitter,
                    &pool_name,
                )
                .await
            });
        }

        let total_queries = ctx.servers.len();

        let result = timeout(Duration::from_millis(ctx.timeout_ms), async {
            let mut failed_count = 0;

            while let Some(result) = futs.next().await {
                match result {
                    Ok(r) => {
                        debug!(
                            server = %r.server_addr,
                            latency_ms = r.latency_ms,
                            "Fastest response, dropping remaining futures"
                        );

                        return Ok(UpstreamResult {
                            response: r.response,
                            server: r.server_addr,
                            latency_ms: r.latency_ms,
                            pool_name: Arc::clone(ctx.pool_name),
                            server_display: r.server_display,
                        });
                    }
                    Err(e) => {
                        failed_count += 1;
                        debug!(
                            error = %e,
                            failed = failed_count,
                            total = total_queries,
                            "Server failed in parallel race"
                        );
                    }
                }
            }

            Err(DomainError::TransportAllServersUnreachable)
        })
        .await;

        match result {
            Ok(r) => r,
            Err(_) => Err(DomainError::TransportTimeout {
                server: format!("parallel({} servers)", total_queries),
            }),
        }
    }
}

impl Default for ParallelStrategy {
    fn default() -> Self {
        Self::new()
    }
}
