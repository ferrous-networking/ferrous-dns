use chrono::{Datelike, Timelike};
use chrono_tz::Tz;
use ferrous_dns_application::ports::{ScheduleProfileRepository, ScheduleStatePort};
use ferrous_dns_domain::{evaluate_slots, GroupOverride, ScheduleAction};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

pub struct ScheduleEvaluatorJob {
    repo: Arc<dyn ScheduleProfileRepository>,
    state: Arc<dyn ScheduleStatePort>,
    interval_secs: u64,
    shutdown: CancellationToken,
    active_groups: Mutex<HashSet<i64>>,
}

impl ScheduleEvaluatorJob {
    pub fn new(
        repo: Arc<dyn ScheduleProfileRepository>,
        state: Arc<dyn ScheduleStatePort>,
    ) -> Self {
        Self {
            repo,
            state,
            interval_secs: 60,
            shutdown: CancellationToken::new(),
            active_groups: Mutex::new(HashSet::new()),
        }
    }

    pub fn with_interval(mut self, interval_secs: u64) -> Self {
        self.interval_secs = interval_secs;
        self
    }

    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.shutdown = token;
        self
    }

    pub async fn start(self: Arc<Self>) {
        info!(
            interval_secs = self.interval_secs,
            "Starting schedule evaluator job"
        );

        let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
        interval.tick().await;

        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("ScheduleEvaluatorJob: shutting down");
                    break;
                }
                _ = interval.tick() => {
                    self.state.sweep_expired();
                    self.evaluate_all_schedules().await;
                }
            }
        }
    }

    async fn evaluate_all_schedules(&self) {
        let assignments = match self.repo.get_all_group_assignments().await {
            Ok(a) => a,
            Err(e) => {
                error!(error = %e, "ScheduleEvaluatorJob: failed to load group assignments");
                return;
            }
        };

        let current_group_ids: HashSet<i64> = assignments.iter().map(|(gid, _)| *gid).collect();

        {
            let mut prev = self.active_groups.lock().await;
            for stale_id in prev.difference(&current_group_ids) {
                self.state.clear(*stale_id);
            }
            *prev = current_group_ids;
        }

        if assignments.is_empty() {
            return;
        }

        for (group_id, profile_id) in &assignments {
            let profile = match self.repo.get_by_id(*profile_id).await {
                Ok(Some(p)) => p,
                Ok(None) => {
                    warn!(
                        profile_id,
                        "ScheduleEvaluatorJob: profile not found, skipping"
                    );
                    continue;
                }
                Err(e) => {
                    error!(error = %e, profile_id, "ScheduleEvaluatorJob: failed to load profile");
                    continue;
                }
            };

            let slots = match self.repo.get_slots(*profile_id).await {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, profile_id, "ScheduleEvaluatorJob: failed to load slots");
                    continue;
                }
            };

            let tz: Tz = match profile.timezone.parse() {
                Ok(tz) => tz,
                Err(_) => {
                    warn!(
                        timezone = %profile.timezone,
                        profile_id,
                        "ScheduleEvaluatorJob: invalid timezone, using UTC"
                    );
                    chrono_tz::UTC
                }
            };

            let now = chrono::Utc::now().with_timezone(&tz);
            let weekday_bit = 1u8 << now.weekday().num_days_from_monday();
            let now_time = format!("{:02}:{:02}", now.hour(), now.minute());

            match evaluate_slots(&slots, weekday_bit, &now_time) {
                Some(ScheduleAction::BlockAll) => {
                    self.state.set(*group_id, GroupOverride::BlockAll);
                }
                Some(ScheduleAction::AllowAll) => {
                    self.state.set(*group_id, GroupOverride::AllowAll);
                }
                None => {
                    self.state.clear(*group_id);
                }
            }
        }
    }
}
