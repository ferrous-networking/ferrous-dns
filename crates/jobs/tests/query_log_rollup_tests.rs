use async_trait::async_trait;
use ferrous_dns_application::ports::QueryLogRollupRepository;
use ferrous_dns_application::use_cases::RollUpQueryLogUseCase;
use ferrous_dns_domain::DomainError;
use ferrous_dns_jobs::QueryLogRollupJob;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, Duration};

/// Records the hour budget of every run.
#[derive(Default)]
struct RecordingRollup {
    runs: Mutex<Vec<u32>>,
}

#[async_trait]
impl QueryLogRollupRepository for RecordingRollup {
    async fn roll_up_hours(&self, max_hours: u32) -> Result<u32, DomainError> {
        self.runs.lock().unwrap().push(max_hours);
        Ok(0)
    }
}

const FIVE_MINUTES: Duration = Duration::from_secs(5 * 60);

#[tokio::test(start_paused = true)]
async fn test_query_log_rollup_job_runs_every_five_minutes_with_a_day_of_hours() {
    let repo = Arc::new(RecordingRollup::default());
    let use_case = Arc::new(RollUpQueryLogUseCase::new(repo.clone()));
    QueryLogRollupJob::new(use_case).spawn();

    sleep(FIVE_MINUTES - Duration::from_secs(1)).await;
    assert!(repo.runs.lock().unwrap().is_empty(), "no run at startup");

    sleep(Duration::from_secs(2)).await;
    assert_eq!(*repo.runs.lock().unwrap(), vec![24]);

    sleep(FIVE_MINUTES).await;
    assert_eq!(*repo.runs.lock().unwrap(), vec![24, 24]);
}
