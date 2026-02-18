use crate::dns::events::QueryEvent;
use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_domain::{QueryLog, QuerySource};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, warn};

pub struct QueryEventLogger {
    log_repo: Arc<dyn QueryLogRepository>,
}

impl QueryEventLogger {
    pub fn new(log_repo: Arc<dyn QueryLogRepository>) -> Self {
        Self { log_repo }
    }

    pub fn start_parallel_batch(
        self,
        mut rx: mpsc::UnboundedReceiver<QueryEvent>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            debug!("QueryEventLogger: Starting parallel batch consumer");

            let mut batch = Vec::with_capacity(100);
            let mut total_events = 0u64;
            let mut total_batches = 0u64;

            while let Some(event) = rx.recv().await {
                batch.push(event);

                while let Ok(event) = rx.try_recv() {
                    batch.push(event);

                    if batch.len() >= 100 {
                        break;
                    }
                }

                if !batch.is_empty() {
                    let events = std::mem::take(&mut batch);
                    let batch_size = events.len();
                    let repo = self.log_repo.clone();

                    total_events += batch_size as u64;
                    total_batches += 1;

                    debug!(
                        batch_size,
                        total_events,
                        total_batches,
                        "QueryEventLogger: Spawning batch processing task"
                    );

                    tokio::spawn(async move {
                        Self::process_batch(repo, events).await;
                    });
                }
            }

            debug!(
                total_events,
                total_batches, "QueryEventLogger: Consumer shutting down gracefully"
            );
        })
    }

    async fn process_batch(repo: Arc<dyn QueryLogRepository>, events: Vec<QueryEvent>) {
        let batch_size = events.len();
        let mut success_count = 0;
        let mut error_count = 0;

        for event in events {
            let query_log = QueryLog {
                id: None,
                domain: event.domain,
                record_type: event.record_type,
                client_ip: "127.0.0.1"
                    .parse::<IpAddr>()
                    .unwrap_or_else(|_| IpAddr::from([127, 0, 0, 1])),
                blocked: false,
                response_time_ms: Some(event.response_time_us),
                cache_hit: false,
                cache_refresh: false,
                dnssec_status: None,
                upstream_server: Some(event.upstream_server),
                response_status: Some(if event.success { "NOERROR" } else { "NXDOMAIN" }),
                timestamp: None,
                query_source: QuerySource::Internal,
            };

            match repo.log_query(&query_log).await {
                Ok(_) => success_count += 1,
                Err(e) => {
                    error_count += 1;
                    warn!(
                        error = %e,
                        domain = %query_log.domain,
                        record_type = ?query_log.record_type,
                        "QueryEventLogger: Failed to log query event (non-critical)"
                    );
                }
            }
        }

        debug!(
            batch_size,
            success_count, error_count, "QueryEventLogger: Batch processing complete"
        );
    }

    #[allow(dead_code)]
    pub fn start_sequential(
        self,
        mut rx: mpsc::UnboundedReceiver<QueryEvent>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            debug!("QueryEventLogger: Starting sequential consumer");

            let mut count = 0u64;

            while let Some(event) = rx.recv().await {
                count += 1;

                let query_log = QueryLog {
                    id: None,
                    domain: event.domain,
                    record_type: event.record_type,
                    client_ip: "127.0.0.1".parse().unwrap(),
                    blocked: false,
                    response_time_ms: Some(event.response_time_us),
                    cache_hit: false,
                    cache_refresh: false,
                    dnssec_status: None,
                    upstream_server: Some(event.upstream_server),
                    response_status: Some(if event.success { "NOERROR" } else { "NXDOMAIN" }),
                    timestamp: None,
                    query_source: QuerySource::Internal,
                };

                if let Err(e) = self.log_repo.log_query(&query_log).await {
                    warn!(
                        error = %e,
                        domain = %query_log.domain,
                        "QueryEventLogger: Failed to log query event"
                    );
                }
            }

            debug!(count, "QueryEventLogger: Sequential consumer shutting down");
        })
    }
}
