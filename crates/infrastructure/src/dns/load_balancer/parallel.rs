use super::query::query_server;
use super::strategy::{QueryContext, UpstreamResult};
use ferrous_dns_domain::DomainError;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

pub struct ParallelStrategy;

impl ParallelStrategy {
    pub fn new() -> Self {
        Self
    }

    pub async fn query_refs(&self, ctx: &QueryContext<'_>) -> Result<UpstreamResult, DomainError> {
        match ctx.servers.len() {
            0 => Err(DomainError::TransportNoHealthyServers),
            1 => {
                let protocol = Arc::clone(ctx.servers[0]);
                let domain = Arc::clone(ctx.domain);
                let record_type = *ctx.record_type;
                let emitter = ctx.emitter.clone();
                let pool_name = Arc::clone(ctx.pool_name);
                let sd = Arc::clone(ctx.server_displays);
                let qb = Arc::clone(&ctx.query_bytes);

                query_server(
                    &protocol,
                    &qb,
                    &domain,
                    &record_type,
                    ctx.timeout_ms,
                    ctx.validator,
                    &emitter,
                    &pool_name,
                    &sd,
                )
                .await
                .map(|r| UpstreamResult {
                    response: r.response,
                    server: r.server_addr,
                    latency_ms: r.latency_ms,
                    pool_name,
                    server_display: r.server_display,
                })
            }
            2 => {
                // Race both upstreams on the stack (zero heap alloc vs FuturesUnordered),
                // preferring the first *successful* answer: if whichever finishes first
                // is an error (e.g. a rejected off-path forgery), fall back to the other
                // instead of failing the whole attempt.
                let s0 = Arc::clone(ctx.servers[0]);
                let s1 = Arc::clone(ctx.servers[1]);
                let domain = Arc::clone(ctx.domain);
                let record_type = *ctx.record_type;
                let emitter0 = ctx.emitter.clone();
                let emitter1 = ctx.emitter.clone();
                let pool_name = Arc::clone(ctx.pool_name);
                let sd = Arc::clone(ctx.server_displays);
                let qb = Arc::clone(&ctx.query_bytes);
                let validator = Arc::clone(ctx.validator);
                let timeout_ms = ctx.timeout_ms;

                let result = timeout(Duration::from_millis(timeout_ms), async move {
                    let f0 = query_server(
                        &s0,
                        &qb,
                        &domain,
                        &record_type,
                        timeout_ms,
                        &validator,
                        &emitter0,
                        &pool_name,
                        &sd,
                    );
                    let f1 = query_server(
                        &s1,
                        &qb,
                        &domain,
                        &record_type,
                        timeout_ms,
                        &validator,
                        &emitter1,
                        &pool_name,
                        &sd,
                    );
                    tokio::pin!(f0, f1);

                    // Track which future settled first so the fallback only re-awaits
                    // the *other* one (re-polling a completed future would panic).
                    let (first_idx, first) = tokio::select! {
                        r = &mut f0 => (0u8, r),
                        r = &mut f1 => (1u8, r),
                    };
                    let winner = match first {
                        Ok(r) => Ok(r),
                        Err(_) if first_idx == 0 => (&mut f1).await,
                        Err(_) => (&mut f0).await,
                    };

                    winner.map(|r| UpstreamResult {
                        response: r.response,
                        server: r.server_addr,
                        latency_ms: r.latency_ms,
                        pool_name: Arc::clone(&pool_name),
                        server_display: r.server_display,
                    })
                })
                .await;

                match result {
                    Ok(r) => r,
                    Err(_) => Err(DomainError::TransportTimeout {
                        server: "parallel(2 servers)".to_string(),
                    }),
                }
            }
            _ => {
                let mut futs = FuturesUnordered::new();

                let per_server_timeout_ms = ctx.timeout_ms;
                let domain_arc = Arc::clone(ctx.domain);
                for &protocol in ctx.servers {
                    let protocol = Arc::clone(protocol);
                    let domain = Arc::clone(&domain_arc);
                    let record_type = *ctx.record_type;
                    let emitter = ctx.emitter.clone();
                    let pool_name = Arc::clone(ctx.pool_name);
                    let server_displays = Arc::clone(ctx.server_displays);
                    let query_bytes = Arc::clone(&ctx.query_bytes);
                    let validator = Arc::clone(ctx.validator);

                    futs.push(async move {
                        query_server(
                            &protocol,
                            &query_bytes,
                            &domain,
                            &record_type,
                            per_server_timeout_ms,
                            &validator,
                            &emitter,
                            &pool_name,
                            &server_displays,
                        )
                        .await
                    });
                }

                let total_queries = ctx.servers.len();

                let result = timeout(Duration::from_millis(ctx.timeout_ms), async {
                    while let Some(result) = futs.next().await {
                        if let Ok(r) = result {
                            return Ok(UpstreamResult {
                                response: r.response,
                                server: r.server_addr,
                                latency_ms: r.latency_ms,
                                pool_name: Arc::clone(ctx.pool_name),
                                server_display: r.server_display,
                            });
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
    }
}

impl Default for ParallelStrategy {
    fn default() -> Self {
        Self::new()
    }
}
