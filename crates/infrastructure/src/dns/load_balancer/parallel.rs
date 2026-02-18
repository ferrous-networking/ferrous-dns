use super::query::query_server;
use super::strategy::UpstreamResult;
use crate::dns::events::QueryEventEmitter;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, warn};

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
        emitter: &QueryEventEmitter,
    ) -> Result<UpstreamResult, DomainError> {
        if servers.is_empty() {
            return Err(DomainError::InvalidDomainName(
                "No upstream servers available".into(),
            ));
        }

        debug!(
            strategy = "parallel",
            servers = servers.len(),
            domain = %domain,
            "Racing all upstreams with immediate cancellation"
        );

        let mut abort_handles = Vec::with_capacity(servers.len());
        let mut futs = FuturesUnordered::new();

        let domain_arc: std::sync::Arc<str> = domain.into();
        for &protocol in servers {
            let protocol = protocol.clone();
            let domain = std::sync::Arc::clone(&domain_arc);
            let record_type = *record_type;
            let emitter = emitter.clone();

            let handle = tokio::spawn(async move {
                query_server(&protocol, &domain, &record_type, timeout_ms, &emitter).await
            });

            abort_handles.push(handle.abort_handle());
            futs.push(handle);
        }

        let total_queries = servers.len();

        let result = timeout(Duration::from_millis(timeout_ms), async {
            let mut failed_count = 0;

            while let Some(join_result) = futs.next().await {
                match join_result {
                    Ok(Ok(r)) => {
                        let canceled = abort_handles.len().saturating_sub(1);

                        for handle in &abort_handles {
                            handle.abort();
                        }

                        debug!(
                            server = %r.server_addr,
                            latency_ms = r.latency_ms,
                            canceled_queries = canceled,
                            "Fastest response, canceled remaining queries"
                        );

                        return Ok(UpstreamResult {
                            response: r.response,
                            server: r.server_addr,
                            latency_ms: r.latency_ms,
                        });
                    }
                    Ok(Err(e)) => {
                        failed_count += 1;
                        debug!(
                            error = %e,
                            failed = failed_count,
                            total = total_queries,
                            "Server failed in parallel race"
                        );
                    }
                    Err(e) => {
                        failed_count += 1;
                        warn!(
                            error = %e,
                            failed = failed_count,
                            total = total_queries,
                            "Task panicked in parallel race"
                        );
                    }
                }
            }

            Err(DomainError::InvalidDomainName(format!(
                "All {} parallel queries failed",
                total_queries
            )))
        })
        .await;

        for handle in &abort_handles {
            handle.abort();
        }

        match result {
            Ok(r) => r,
            Err(_) => Err(DomainError::InvalidDomainName(format!(
                "Parallel query timeout after {}ms ({} queries)",
                timeout_ms, total_queries
            ))),
        }
    }
}

impl Default for ParallelStrategy {
    fn default() -> Self {
        Self::new()
    }
}
