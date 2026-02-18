use crate::{ClientSyncJob, QueryLogRetentionJob, RetentionJob};
use std::sync::Arc;
use tracing::info;

pub struct JobRunner {
    client_sync: Option<ClientSyncJob>,
    retention: Option<RetentionJob>,
    query_log_retention: Option<QueryLogRetentionJob>,
}

impl JobRunner {
    pub fn new() -> Self {
        Self {
            client_sync: None,
            retention: None,
            query_log_retention: None,
        }
    }

    pub fn with_client_sync(mut self, job: ClientSyncJob) -> Self {
        self.client_sync = Some(job);
        self
    }

    pub fn with_retention(mut self, job: RetentionJob) -> Self {
        self.retention = Some(job);
        self
    }

    pub fn with_query_log_retention(mut self, job: QueryLogRetentionJob) -> Self {
        self.query_log_retention = Some(job);
        self
    }

    pub async fn start(self) {
        info!("Starting background job runner");

        if let Some(job) = self.client_sync {
            Arc::new(job).start().await;
        }

        if let Some(job) = self.retention {
            Arc::new(job).start().await;
        }

        if let Some(job) = self.query_log_retention {
            Arc::new(job).start().await;
        }

        info!("All background jobs started");
    }
}

impl Default for JobRunner {
    fn default() -> Self {
        Self::new()
    }
}
