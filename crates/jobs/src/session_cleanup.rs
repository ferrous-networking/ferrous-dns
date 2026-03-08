use ferrous_dns_application::ports::SessionRepository;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info};

/// Periodically deletes expired auth sessions from the database.
pub struct SessionCleanupJob {
    session_repo: Arc<dyn SessionRepository>,
    interval_secs: u64,
    shutdown: CancellationToken,
}

impl SessionCleanupJob {
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self {
            session_repo,
            interval_secs: 3600,
            shutdown: CancellationToken::new(),
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
            "Starting session cleanup job"
        );

        let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
        loop {
            tokio::select! {
                _ = self.shutdown.cancelled() => {
                    info!("SessionCleanupJob: shutting down");
                    break;
                }
                _ = interval.tick() => {
                    match self.session_repo.delete_expired().await {
                        Ok(count) => {
                            if count > 0 {
                                info!(deleted = count, "Expired sessions cleaned up");
                            } else {
                                debug!("No expired sessions to clean up");
                            }
                        }
                        Err(e) => {
                            error!(error = %e, "Session cleanup failed");
                        }
                    }
                }
            }
        }
    }
}
