use ferrous_dns_domain::{DomainError, SafeSearchConfig};
use std::sync::Arc;

use crate::ports::{GroupRepository, SafeSearchConfigRepository};

/// Retrieves Safe Search configurations, optionally filtered by group.
pub struct GetSafeSearchConfigsUseCase {
    repo: Arc<dyn SafeSearchConfigRepository>,
    group_repo: Arc<dyn GroupRepository>,
}

impl GetSafeSearchConfigsUseCase {
    /// Creates a new `GetSafeSearchConfigsUseCase`.
    pub fn new(
        repo: Arc<dyn SafeSearchConfigRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self { repo, group_repo }
    }

    /// Returns all Safe Search configurations across every group.
    pub async fn get_all(&self) -> Result<Vec<SafeSearchConfig>, DomainError> {
        self.repo.get_all().await
    }

    /// Returns all Safe Search configurations for a single group.
    ///
    /// Returns [`DomainError::GroupNotFound`] if `group_id` does not exist.
    pub async fn get_by_group(&self, group_id: i64) -> Result<Vec<SafeSearchConfig>, DomainError> {
        self.group_repo
            .get_by_id(group_id)
            .await?
            .ok_or(DomainError::GroupNotFound(group_id))?;
        self.repo.get_by_group(group_id).await
    }
}
