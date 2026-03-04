use ferrous_dns_domain::{DomainError, SafeSearchConfig, SafeSearchEngine, YouTubeMode};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{GroupRepository, SafeSearchConfigRepository, SafeSearchEnginePort};

/// Enables or disables a Safe Search engine for a specific group.
///
/// After persisting the change, reloads the in-memory Safe Search index so
/// the new configuration takes effect on the next DNS query without restart.
pub struct ToggleSafeSearchUseCase {
    repo: Arc<dyn SafeSearchConfigRepository>,
    group_repo: Arc<dyn GroupRepository>,
    engine_port: Arc<dyn SafeSearchEnginePort>,
}

impl ToggleSafeSearchUseCase {
    /// Creates a new `ToggleSafeSearchUseCase`.
    pub fn new(
        repo: Arc<dyn SafeSearchConfigRepository>,
        group_repo: Arc<dyn GroupRepository>,
        engine_port: Arc<dyn SafeSearchEnginePort>,
    ) -> Self {
        Self {
            repo,
            group_repo,
            engine_port,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        group_id: i64,
        engine: SafeSearchEngine,
        enabled: bool,
        youtube_mode: YouTubeMode,
    ) -> Result<SafeSearchConfig, DomainError> {
        self.group_repo
            .get_by_id(group_id)
            .await?
            .ok_or(DomainError::GroupNotFound(group_id))?;

        let config = self
            .repo
            .upsert(group_id, engine, enabled, youtube_mode)
            .await?;

        info!(
            config_id = ?config.id,
            group_id = group_id,
            engine = engine.to_str(),
            enabled = enabled,
            "Safe Search configuration updated"
        );

        self.engine_port.reload().await?;

        Ok(config)
    }
}
