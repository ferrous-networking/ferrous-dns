use crate::{
    BlocklistSyncJob, CacheMaintenanceJob, ClientSyncJob, QueryLogRetentionJob, RetentionJob,
    WalCheckpointJob,
};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;

pub trait SpawnableJob: Send + 'static {
    fn with_cancellation(self, token: CancellationToken) -> Self;
    fn start_job(self: Arc<Self>) -> tokio::task::JoinHandle<()>;
}

macro_rules! impl_spawnable_job {
    ($t:ty) => {
        impl SpawnableJob for $t {
            fn with_cancellation(self, token: CancellationToken) -> Self {
                self.with_cancellation(token)
            }

            fn start_job(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
                tokio::spawn(async move { self.start().await })
            }
        }
    };
}

impl_spawnable_job!(ClientSyncJob);
impl_spawnable_job!(RetentionJob);
impl_spawnable_job!(QueryLogRetentionJob);
impl_spawnable_job!(BlocklistSyncJob);
impl_spawnable_job!(WalCheckpointJob);
impl_spawnable_job!(CacheMaintenanceJob);

fn spawn_job<J: SpawnableJob>(job: Option<J>, shutdown: &Option<CancellationToken>) {
    if let Some(job) = job {
        let job = match shutdown {
            Some(token) => job.with_cancellation(token.clone()),
            None => job,
        };
        Arc::new(job).start_job();
    }
}

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

        spawn_job(self.client_sync, &self.shutdown);
        spawn_job(self.retention, &self.shutdown);
        spawn_job(self.query_log_retention, &self.shutdown);
        spawn_job(self.blocklist_sync, &self.shutdown);
        spawn_job(self.wal_checkpoint, &self.shutdown);
        spawn_job(self.cache_maintenance, &self.shutdown);

        info!("All background jobs started");
    }
}

impl Default for JobRunner {
    fn default() -> Self {
        Self::new()
    }
}
