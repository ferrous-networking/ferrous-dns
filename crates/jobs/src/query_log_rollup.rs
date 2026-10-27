use ferrous_dns_application::use_cases::RollUpQueryLogUseCase;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};

/// Cadence of the job. The top lists read the hours it has not aggregated yet from
/// the raw log, so this bounds how much of the log they scan past the last hour held.
const ROLLUP_INTERVAL_SECS: u64 = 5 * 60;

/// Hours aggregated per run at most. A day per run fills in a month of history in
/// about two and a half hours, without any one run reading the whole log.
const MAX_HOURS_PER_RUN: u32 = 24;

pub struct QueryLogRollupJob {
    roll_up: Arc<RollUpQueryLogUseCase>,
}

impl QueryLogRollupJob {
    pub fn new(roll_up: Arc<RollUpQueryLogUseCase>) -> Self {
        Self { roll_up }
    }

    pub fn spawn(self) {
        info!(
            interval_secs = ROLLUP_INTERVAL_SECS,
            max_hours_per_run = MAX_HOURS_PER_RUN,
            "Starting query log rollup job"
        );

        tokio::spawn(async move {
            let period = Duration::from_secs(ROLLUP_INTERVAL_SECS);
            let mut interval =
                tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            loop {
                interval.tick().await;
                match self.roll_up.execute(MAX_HOURS_PER_RUN).await {
                    Ok(0) => debug!("No query log hour left to roll up"),
                    Ok(hours) => info!(hours, "Query log hours rolled up"),
                    Err(e) => error!(error = %e, "Query log rollup failed"),
                }
            }
        });
    }
}
