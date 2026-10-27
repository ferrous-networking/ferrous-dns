use async_trait::async_trait;
use ferrous_dns_domain::DomainError;

/// Gives the free pages that deletes leave in the database file back to the disk.
#[async_trait]
pub trait FreeSpaceReclaimer: Send + Sync {
    /// Returns how many pages it gave back: 0 for a database that cannot give any.
    async fn reclaim_free_space(&self) -> Result<u64, DomainError>;
}
