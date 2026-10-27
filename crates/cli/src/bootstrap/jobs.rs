use ferrous_dns_domain::Config;
use ferrous_dns_jobs::{
    BlocklistSyncJob, ClientSyncJob, QueryLogRetentionJob, QueryLogRollupJob, RetentionJob,
    ScheduleEvaluatorJob, SessionCleanupJob, WalCheckpointJob,
};
use sqlx::SqlitePool;
use tracing::info;

use crate::wiring::{Repositories, UseCases};

/// Starts the periodic background jobs. The detector eviction jobs start with
/// their detectors in `DnsServices::new`, and the cache keeps itself: its
/// worker starts with the cache.
pub fn spawn_jobs(
    use_cases: &UseCases,
    repos: &Repositories,
    config: &Config,
    wal_pool: SqlitePool,
) {
    ClientSyncJob::new(use_cases.sync_arp.clone(), use_cases.sync_hostnames.clone()).spawn();
    RetentionJob::new(use_cases.cleanup_clients.clone(), 30).spawn();
    QueryLogRetentionJob::new(
        use_cases.cleanup_query_logs.clone(),
        config.database.queries_log_stored,
    )
    .spawn();
    QueryLogRollupJob::new(use_cases.roll_up_query_log.clone()).spawn();
    BlocklistSyncJob::new(repos.block_filter_engine.clone()).spawn();
    WalCheckpointJob::new(wal_pool, config.database.wal_checkpoint_interval_secs).spawn();
    ScheduleEvaluatorJob::new(repos.schedule_profile.clone(), repos.schedule_state.clone()).spawn();
    SessionCleanupJob::new(repos.session.clone()).spawn();

    info!("All background jobs started");
}
