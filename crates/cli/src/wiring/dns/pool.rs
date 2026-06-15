use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::{
    events::QueryEventEmitter, query_logger::QueryEventLogger, HealthChecker, PoolManager,
};
use std::sync::Arc;
use tracing::info;

use crate::wiring::Repositories;

pub(super) fn setup_event_logger(repos: &Repositories) -> QueryEventEmitter {
    info!("Query event logging enabled (parallel batch processing - 20,000+ queries/sec)");
    let (emitter, event_rx) = QueryEventEmitter::new_enabled();
    let logger = QueryEventLogger::new(repos.query_log.clone());
    tokio::spawn(async move {
        if let Err(e) = logger.start_parallel_batch(event_rx).await {
            tracing::error!(error = %e, "Query event logger failed");
        }
    });
    info!("Query event logger started - logging client DNS queries");
    emitter
}

pub(super) fn setup_health_checker(config: &Config) -> Option<Arc<HealthChecker>> {
    let checker = Arc::new(HealthChecker::new(
        config.dns.health_check.failure_threshold,
        config.dns.health_check.success_threshold,
    ));
    info!(
        interval_seconds = config.dns.health_check.interval,
        timeout_ms = config.dns.health_check.timeout,
        "Health checker enabled"
    );
    Some(checker)
}

pub(super) async fn setup_pool_manager(
    config: &Config,
    health_checker: Option<Arc<HealthChecker>>,
    emitter: QueryEventEmitter,
) -> anyhow::Result<Arc<PoolManager>> {
    Ok(Arc::new(
        PoolManager::new(config.dns.pools.clone(), health_checker, emitter).await?,
    ))
}

pub(super) fn start_health_checker_task(
    health_checker: Option<Arc<HealthChecker>>,
    pool_manager: &Arc<PoolManager>,
    config: &Config,
) {
    if let Some(checker) = health_checker {
        // Weak ref so the probe loop reads the live pool set each tick (picking up
        // hot reloads) without forming an Arc cycle with the PoolManager.
        let pm_weak = Arc::downgrade(pool_manager);
        let checker_clone = checker.clone();
        let interval = config.dns.health_check.interval;
        let timeout = config.dns.health_check.timeout;
        tokio::spawn(async move {
            checker_clone
                .run(
                    move || {
                        pm_weak
                            .upgrade()
                            .map(|pm| pm.get_all_arc_protocols())
                            .unwrap_or_default()
                    },
                    interval,
                    timeout,
                )
                .await;
        });
        info!("Health checker background task started");
    }
}
