use ferrous_dns_application::ports::CacheMaintenancePort;
use ferrous_dns_domain::Config;
use ferrous_dns_jobs::{
    BlocklistSyncJob, CacheMaintenanceJob, ClientSyncJob, JobRunner, NxdomainHijackEvictionJob,
    QueryLogRetentionJob, ResponseIpFilterEvictionJob, RetentionJob, ScheduleEvaluatorJob,
    SessionCleanupJob, TunnelingEvictionJob, WalCheckpointJob,
};
use sqlx::SqlitePool;
use std::sync::Arc;

use crate::wiring::{Repositories, UseCases};

#[allow(clippy::too_many_arguments)]
pub fn build_job_runner(
    use_cases: &UseCases,
    repos: &Repositories,
    config: &Config,
    wal_pool: SqlitePool,
    cache_maintenance: Option<Arc<dyn CacheMaintenancePort>>,
    tunneling_eviction: Option<TunnelingEvictionJob>,
    nxdomain_hijack_eviction: Option<NxdomainHijackEvictionJob>,
    response_ip_filter_eviction: Option<ResponseIpFilterEvictionJob>,
) -> JobRunner {
    let mut runner = JobRunner::new()
        .with_client_sync(ClientSyncJob::new(
            use_cases.sync_arp.clone(),
            use_cases.sync_hostnames.clone(),
        ))
        .with_retention(RetentionJob::new(use_cases.cleanup_clients.clone(), 30))
        .with_query_log_retention(QueryLogRetentionJob::new(
            use_cases.cleanup_query_logs.clone(),
            config.database.queries_log_stored,
        ))
        .with_blocklist_sync(BlocklistSyncJob::new(repos.block_filter_engine.clone()))
        .with_wal_checkpoint(WalCheckpointJob::new(
            wal_pool,
            config.database.wal_checkpoint_interval_secs,
        ))
        .with_schedule_evaluator(ScheduleEvaluatorJob::new(
            repos.schedule_profile.clone(),
            repos.schedule_state.clone(),
        ))
        .with_session_cleanup(SessionCleanupJob::new(repos.session.clone()).with_interval(3600));

    if let Some(maintenance) = cache_maintenance {
        runner = runner.with_cache_maintenance(
            CacheMaintenanceJob::new(maintenance)
                .with_intervals(60, config.dns.cache_compaction_interval),
        );
    }

    if let Some(eviction) = tunneling_eviction {
        runner = runner.with_tunneling_eviction(eviction);
    }

    if let Some(eviction) = nxdomain_hijack_eviction {
        runner = runner.with_nxdomain_hijack_eviction(eviction);
    }

    if let Some(eviction) = response_ip_filter_eviction {
        runner = runner.with_response_ip_filter_eviction(eviction);
    }

    runner
}
