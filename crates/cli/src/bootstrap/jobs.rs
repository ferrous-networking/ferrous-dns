use ferrous_dns_application::ports::CacheMaintenancePort;
use ferrous_dns_domain::Config;
use ferrous_dns_jobs::{
    BlocklistSyncJob, CacheMaintenanceJob, ClientSyncJob, QueryLogRetentionJob, RetentionJob,
    ScheduleEvaluatorJob, SessionCleanupJob, WalCheckpointJob, MAINTENANCE_INTERVAL_SECS,
};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::info;

use crate::wiring::{Repositories, UseCases};

/// Starts the periodic background jobs. The detector eviction jobs start with
/// their detectors in `DnsServices::new`.
pub fn spawn_jobs(
    use_cases: &UseCases,
    repos: &Repositories,
    config: &Config,
    wal_pool: SqlitePool,
    cache_maintenance: Option<Arc<dyn CacheMaintenancePort>>,
) {
    ClientSyncJob::new(use_cases.sync_arp.clone(), use_cases.sync_hostnames.clone()).spawn();
    RetentionJob::new(use_cases.cleanup_clients.clone(), 30).spawn();
    QueryLogRetentionJob::new(
        use_cases.cleanup_query_logs.clone(),
        config.database.queries_log_stored,
    )
    .spawn();
    BlocklistSyncJob::new(repos.block_filter_engine.clone()).spawn();
    WalCheckpointJob::new(wal_pool, config.database.wal_checkpoint_interval_secs).spawn();
    if let Some(maintenance) = cache_maintenance {
        CacheMaintenanceJob::new(
            maintenance,
            MAINTENANCE_INTERVAL_SECS,
            config.dns.cache_compaction_interval,
        )
        .spawn();
    }
    ScheduleEvaluatorJob::new(repos.schedule_profile.clone(), repos.schedule_state.clone()).spawn();
    SessionCleanupJob::new(repos.session.clone()).spawn();

    info!("All background jobs started");
}
