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

    /// Query all servers in parallel, return fastest response.
    ///
    /// ## Phase 5: Query Event Logging
    ///
    /// The `emitter` parameter is cloned and passed to each spawned task to enable
    /// comprehensive logging of all parallel DNS queries.
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
        debug!(strategy = "parallel", servers = servers.len(), domain = %domain, "Racing all upstreams");

        let mut abort_handles = Vec::with_capacity(servers.len());
        let mut futs = FuturesUnordered::new();

        for &protocol in servers {
            let protocol = protocol.clone();
            let domain = domain.to_string();
            let record_type = record_type.clone();
            let emitter = emitter.clone(); // Clone emitter for spawned task
            let handle = tokio::spawn(async move {
                query_server(&protocol, &domain, &record_type, timeout_ms, &emitter).await
            });
            abort_handles.push(handle.abort_handle());
            futs.push(handle);
        }

        let result = timeout(Duration::from_millis(timeout_ms), async {
            while let Some(join_result) = futs.next().await {
                match join_result {
                    Ok(Ok(r)) => {
                        debug!(server = %r.server_addr, latency_ms = r.latency_ms, "Fastest response");
                        return Ok(UpstreamResult { response: r.response, server: r.server_addr, latency_ms: r.latency_ms });
                    }
                    Ok(Err(e)) => { debug!(error = %e, "Server failed"); }
                    Err(e) => { warn!(error = %e, "Task panicked"); }
                }
            }
            Err(DomainError::InvalidDomainName("All parallel queries failed".into()))
        }).await;

        for handle in &abort_handles {
            handle.abort();
        }

        match result {
            Ok(r) => r,
            Err(_) => Err(DomainError::InvalidDomainName(format!(
                "Parallel query timeout after {}ms",
                timeout_ms
            ))),
        }
    }
}

impl Default for ParallelStrategy {
    fn default() -> Self {
        Self::new()
    }
}
