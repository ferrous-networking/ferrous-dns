use ferrous_dns_domain::{Client, DomainError, Group};
use std::sync::Arc;
use tracing::instrument;

use crate::ports::GroupRepository;

pub struct GetGroupsUseCase {
    group_repo: Arc<dyn GroupRepository>,
}

impl GetGroupsUseCase {
    pub fn new(group_repo: Arc<dyn GroupRepository>) -> Self {
        Self { group_repo }
    }

    #[instrument(skip(self))]
    pub async fn get_all(&self) -> Result<Vec<Group>, DomainError> {
        self.group_repo.get_all().await
    }

    #[instrument(skip(self))]
    pub async fn get_all_with_client_counts(&self) -> Result<Vec<(Group, u64)>, DomainError> {
        self.group_repo.get_all_with_client_counts().await
    }

    #[instrument(skip(self))]
    pub async fn get_by_id(&self, id: i64) -> Result<Option<Group>, DomainError> {
        self.group_repo.get_by_id(id).await
    }

    #[instrument(skip(self))]
    pub async fn get_clients_in_group(&self, group_id: i64) -> Result<Vec<Client>, DomainError> {
        self.group_repo.get_clients_in_group(group_id).await
    }

    #[instrument(skip(self))]
    pub async fn count_clients_in_group(&self, group_id: i64) -> Result<u64, DomainError> {
        self.group_repo.count_clients_in_group(group_id).await
    }
}
