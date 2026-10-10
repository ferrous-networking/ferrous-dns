use std::sync::Arc;
use tracing::instrument;

use super::session_factory::{is_expired, is_older_than};
use crate::ports::SessionRepository;
use ferrous_dns_domain::{AuthSession, DomainError};

/// `last_seen_at` only feeds the session list, so refreshing it once a minute keeps
/// every authenticated request from queueing for SQLite's write lock.
const LAST_SEEN_REFRESH_SECS: i64 = 60;

/// Validates a session ID and refreshes its `last_seen_at` timestamp at most once a minute.
pub struct ValidateSessionUseCase {
    session_repo: Arc<dyn SessionRepository>,
}

impl ValidateSessionUseCase {
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self { session_repo }
    }

    /// Returns the session if valid and not expired. Updates a `last_seen_at` older than a minute.
    ///
    /// Expiration is checked by parsing the `expires_at` timestamp.
    /// If the timestamp cannot be parsed, the session is treated as expired (fail-closed).
    #[instrument(skip(self))]
    pub async fn execute(&self, session_id: &str) -> Result<AuthSession, DomainError> {
        let session = self
            .session_repo
            .get_by_id(session_id)
            .await?
            .ok_or(DomainError::SessionNotFound)?;

        if is_expired(&session.expires_at) {
            self.session_repo.delete(session_id).await?;
            return Err(DomainError::SessionNotFound);
        }

        if is_older_than(&session.last_seen_at, LAST_SEEN_REFRESH_SECS) {
            self.session_repo.update_last_seen(session_id).await?;
        }
        Ok(session)
    }
}
