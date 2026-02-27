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
        mut rx: mpsc::Receiver<QueryEvent>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            debug!("QueryEventLogger: Starting parallel batch consumer");

            let mut batch: Vec<QueryEvent> = Vec::with_capacity(100);
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
                    let batch_size = batch.len();
                    let repo = self.log_repo.clone();

                    total_events += batch_size as u64;
                    total_batches += 1;

                    debug!(
                        batch_size,
                        total_events, total_batches, "QueryEventLogger: Processing batch"
                    );

                    Self::process_batch(&repo, &mut batch).await;
                }
            }

            debug!(
                total_events,
                total_batches, "QueryEventLogger: Consumer shutting down gracefully"
            );
        })
    }

    async fn process_batch(repo: &Arc<dyn QueryLogRepository>, batch: &mut Vec<QueryEvent>) {
        let batch_size = batch.len();
        let mut success_count = 0;
        let mut error_count = 0;

        for event in batch.iter() {
            let query_log = QueryLog {
                id: None,
                domain: event.domain.clone(),
                record_type: event.record_type,
                client_ip: IpAddr::from([127, 0, 0, 1]),
                client_hostname: None,
                blocked: false,
                response_time_us: Some(event.response_time_us),
                cache_hit: false,
                cache_refresh: false,
                dnssec_status: None,
                upstream_server: Some(Arc::clone(&event.upstream_server)),
                upstream_pool: event.pool_name.clone(),
                response_status: Some(if event.success { "NOERROR" } else { "NXDOMAIN" }),
                timestamp: None,
                query_source: QuerySource::Internal,
                group_id: None,
                block_source: None,
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

        batch.clear();

        debug!(
            batch_size,
            success_count, error_count, "QueryEventLogger: Batch processing complete"
        );
    }
}
