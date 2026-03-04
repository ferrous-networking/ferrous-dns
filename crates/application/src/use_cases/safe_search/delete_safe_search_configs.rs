use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{GroupRepository, SafeSearchConfigRepository, SafeSearchEnginePort};

/// Removes all Safe Search configurations for a group.
///
/// After persisting the deletion, reloads the in-memory Safe Search index so
/// the change takes effect on the next DNS query without restart.
pub struct DeleteSafeSearchConfigsUseCase {
    repo: Arc<dyn SafeSearchConfigRepository>,
    group_repo: Arc<dyn GroupRepository>,
    engine_port: Arc<dyn SafeSearchEnginePort>,
}

impl DeleteSafeSearchConfigsUseCase {
    /// Creates a new `DeleteSafeSearchConfigsUseCase`.
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

    /// Deletes all Safe Search configurations for the given group and reloads the index.
    #[instrument(skip(self))]
    pub async fn execute(&self, group_id: i64) -> Result<(), DomainError> {
        self.group_repo
            .get_by_id(group_id)
            .await?
            .ok_or(DomainError::GroupNotFound(group_id))?;

        self.repo.delete_by_group(group_id).await?;

        info!(
            group_id = group_id,
            "Safe Search configurations removed for group"
        );

        self.engine_port.reload().await?;

        Ok(())
    }
}
