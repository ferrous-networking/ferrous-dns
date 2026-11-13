use ferrous_dns_application::ports::{MfaRepository, SessionRepository};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info};

const INTERVAL_SECS: u64 = 3600;

/// Periodically deletes expired auth sessions and second-factor or passkey
/// challenges from the database.
pub struct SessionCleanupJob {
    session_repo: Arc<dyn SessionRepository>,
    mfa_repo: Arc<dyn MfaRepository>,
}

impl SessionCleanupJob {
    pub fn new(session_repo: Arc<dyn SessionRepository>, mfa_repo: Arc<dyn MfaRepository>) -> Self {
        Self {
            session_repo,
            mfa_repo,
        }
    }

    pub fn spawn(self) {
        info!(
            interval_secs = INTERVAL_SECS,
            "Starting session cleanup job"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(INTERVAL_SECS));
            loop {
                interval.tick().await;
                match self.session_repo.delete_expired().await {
                    Ok(0) => debug!("No expired sessions to clean up"),
                    Ok(count) => info!(deleted = count, "Expired sessions cleaned up"),
                    Err(e) => error!(error = %e, "Session cleanup failed"),
                }
                match self.mfa_repo.delete_expired_challenges().await {
                    Ok(0) => debug!("No expired login challenges to clean up"),
                    Ok(count) => info!(deleted = count, "Expired login challenges cleaned up"),
                    Err(e) => error!(error = %e, "Login challenge cleanup failed"),
                }
            }
        });
    }
}
