use std::sync::Arc;
use tracing::instrument;

use crate::ports::SessionRepository;
use ferrous_dns_domain::{AuthSession, DomainError};

/// Validates a session ID and refreshes its `last_seen_at` timestamp.
pub struct ValidateSessionUseCase {
    session_repo: Arc<dyn SessionRepository>,
}

impl ValidateSessionUseCase {
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self { session_repo }
    }

    /// Returns the session if valid and not expired. Updates `last_seen_at`.
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

        self.session_repo.update_last_seen(session_id).await?;
        Ok(session)
    }
}

/// Checks if an expiry timestamp has passed. Returns `true` (expired) on parse failure (fail-closed).
fn is_expired(expires_at: &str) -> bool {
    chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
        .map(|exp| chrono::Utc::now().naive_utc() > exp)
        .unwrap_or(true)
}
