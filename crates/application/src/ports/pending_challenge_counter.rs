use async_trait::async_trait;
use ferrous_dns_domain::DomainError;

/// Counts the passwordless passkey ceremonies still pending. Anyone can start
/// one, so the count is what keeps them from piling up without bound.
#[async_trait]
pub trait PendingChallengeCounter: Send + Sync {
    /// Unexpired challenges not yet tied to a user.
    async fn count_pending_anonymous(&self) -> Result<u64, DomainError>;
}
