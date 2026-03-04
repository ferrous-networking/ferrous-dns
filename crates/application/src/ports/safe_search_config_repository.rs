use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, SafeSearchConfig, SafeSearchEngine, YouTubeMode};

/// Persistence port for per-group Safe Search configuration.
#[async_trait]
pub trait SafeSearchConfigRepository: Send + Sync {
    /// Returns all Safe Search configurations across every group.
    async fn get_all(&self) -> Result<Vec<SafeSearchConfig>, DomainError>;

    /// Returns Safe Search configurations for a specific group.
    async fn get_by_group(&self, group_id: i64) -> Result<Vec<SafeSearchConfig>, DomainError>;

    /// Inserts or updates the configuration for `(group_id, engine)`.
    async fn upsert(
        &self,
        group_id: i64,
        engine: SafeSearchEngine,
        enabled: bool,
        youtube_mode: YouTubeMode,
    ) -> Result<SafeSearchConfig, DomainError>;

    /// Removes all Safe Search configurations for a group.
    async fn delete_by_group(&self, group_id: i64) -> Result<(), DomainError>;
}
