use async_trait::async_trait;
use ferrous_dns_domain::{AuthSession, DomainError};

/// Port for managing browser authentication sessions in persistent storage.
#[async_trait]
pub trait SessionRepository: Send + Sync {
    /// Persist a new session.
    async fn create(&self, session: &AuthSession) -> Result<(), DomainError>;

    /// Retrieve a session by its ID. Returns `None` if not found.
    async fn get_by_id(&self, id: &str) -> Result<Option<AuthSession>, DomainError>;

    /// Update the `last_seen_at` timestamp for keep-alive tracking.
    async fn update_last_seen(&self, id: &str) -> Result<(), DomainError>;

    /// Delete a single session (logout).
    async fn delete(&self, id: &str) -> Result<(), DomainError>;

    /// Delete all sessions that have passed their `expires_at` timestamp.
    /// Returns the number of sessions removed.
    async fn delete_expired(&self) -> Result<u64, DomainError>;

    /// List all non-expired sessions (for the Active Sessions UI).
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError>;
}
