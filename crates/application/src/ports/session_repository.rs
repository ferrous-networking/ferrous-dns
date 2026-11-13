use async_trait::async_trait;
use ferrous_dns_domain::{AuthSession, DomainError};

/// Port for managing browser authentication sessions in persistent storage.
///
/// Every `id` here is a session handle (`AuthSession::id`), never the token a
/// cookie carries: callers hash the token with `session_handle` first.
#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create(&self, session: &AuthSession) -> Result<(), DomainError>;

    async fn get_by_id(&self, id: &str) -> Result<Option<AuthSession>, DomainError>;

    /// Update the `last_seen_at` timestamp for keep-alive tracking.
    async fn update_last_seen(&self, id: &str) -> Result<(), DomainError>;

    /// Delete a single session (logout).
    async fn delete(&self, id: &str) -> Result<(), DomainError>;

    /// Delete all sessions that have passed their `expires_at` timestamp.
    /// Returns the number of sessions removed.
    async fn delete_expired(&self) -> Result<u64, DomainError>;

    /// Delete every session of `username` except `keep_id`.
    /// Returns the number of sessions removed.
    async fn delete_other_sessions(
        &self,
        username: &str,
        keep_id: &str,
    ) -> Result<u64, DomainError>;

    /// List all non-expired sessions (for the Active Sessions UI).
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError>;
}
