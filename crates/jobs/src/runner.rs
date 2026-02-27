use crate::{
    BlocklistSyncJob, CacheMaintenanceJob, ClientSyncJob, QueryLogRetentionJob, RetentionJob,
    WalCheckpointJob,
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;

pub struct JobRunner {
    client_sync: Option<ClientSyncJob>,
    retention: Option<RetentionJob>,
    query_log_retention: Option<QueryLogRetentionJob>,
    blocklist_sync: Option<BlocklistSyncJob>,
    wal_checkpoint: Option<WalCheckpointJob>,
    cache_maintenance: Option<CacheMaintenanceJob>,
    shutdown: Option<CancellationToken>,
}

impl JobRunner {
    pub fn new() -> Self {
        Self {
            client_sync: None,
            retention: None,
            query_log_retention: None,
            blocklist_sync: None,
            wal_checkpoint: None,
            cache_maintenance: None,
            shutdown: None,
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

    pub fn with_blocklist_sync(mut self, job: BlocklistSyncJob) -> Self {
        self.blocklist_sync = Some(job);
        self
    }

    pub fn with_wal_checkpoint(mut self, job: WalCheckpointJob) -> Self {
        self.wal_checkpoint = Some(job);
        self
    }

    pub fn with_cache_maintenance(mut self, job: CacheMaintenanceJob) -> Self {
        self.cache_maintenance = Some(job);
        self
    }

    pub fn with_shutdown_token(mut self, token: CancellationToken) -> Self {
        self.shutdown = Some(token);
        self
    }

    pub async fn start(self) {
        info!("Starting background job runner");

        if let Some(job) = self.client_sync {
            let job = match &self.shutdown {
                Some(token) => job.with_cancellation(token.clone()),
                None => job,
            };
            Arc::new(job).start().await;
        }

        if let Some(job) = self.retention {
            let job = match &self.shutdown {
                Some(token) => job.with_cancellation(token.clone()),
                None => job,
            };
            Arc::new(job).start().await;
        }

        if let Some(job) = self.query_log_retention {
            let job = match &self.shutdown {
                Some(token) => job.with_cancellation(token.clone()),
                None => job,
            };
            Arc::new(job).start().await;
        }

        if let Some(job) = self.blocklist_sync {
            let job = match &self.shutdown {
                Some(token) => job.with_cancellation(token.clone()),
                None => job,
            };
            Arc::new(job).start().await;
        }

        if let Some(job) = self.wal_checkpoint {
            let job = match &self.shutdown {
                Some(token) => job.with_cancellation(token.clone()),
                None => job,
            };
            Arc::new(job).start().await;
        }

        if let Some(job) = self.cache_maintenance {
            let job = match &self.shutdown {
                Some(token) => job.with_cancellation(token.clone()),
                None => job,
            };
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
