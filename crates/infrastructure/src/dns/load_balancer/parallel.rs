use super::query::query_server;
use super::strategy::UpstreamResult;
use crate::dns::events::QueryEventEmitter;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::time::Duration;
use tokio::time::timeout;
use tracing::debug;

pub struct ParallelStrategy;

impl ParallelStrategy {
    pub fn new() -> Self {
        Self
    }

    pub async fn query_refs(
        &self,
        servers: &[&DnsProtocol],
        domain: &str,
        record_type: &RecordType,
        timeout_ms: u64,
        dnssec_ok: bool,
        emitter: &QueryEventEmitter,
    ) -> Result<UpstreamResult, DomainError> {
        if servers.is_empty() {
            return Err(DomainError::TransportNoHealthyServers);
        }

        debug!(
            strategy = "parallel",
            servers = servers.len(),
            domain = %domain,
            "Racing all upstreams with immediate cancellation"
        );

        let mut futs = FuturesUnordered::new();

        let per_server_timeout_ms = timeout_ms.saturating_mul(2);

        let domain_arc: std::sync::Arc<str> = domain.into();
        for &protocol in servers {
            let protocol = protocol.clone();
            let domain = std::sync::Arc::clone(&domain_arc);
            let record_type = *record_type;
            let emitter = emitter.clone();

            futs.push(async move {
                query_server(
                    &protocol,
                    &domain,
                    &record_type,
                    per_server_timeout_ms,
                    dnssec_ok,
                    &emitter,
                )
                .await
            });
        }

        let total_queries = servers.len();

        let result = timeout(Duration::from_millis(timeout_ms), async {
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
