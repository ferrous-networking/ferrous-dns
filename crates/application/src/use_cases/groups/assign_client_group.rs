use ferrous_dns_domain::{Client, DomainError};
use std::sync::Arc;
use tracing::{error, info, instrument, warn};

use crate::ports::{BlockFilterEnginePort, ClientRepository, GroupRepository};

pub struct AssignClientGroupUseCase {
    client_repo: Arc<dyn ClientRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl AssignClientGroupUseCase {
    pub fn new(
        client_repo: Arc<dyn ClientRepository>,
        group_repo: Arc<dyn GroupRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            client_repo,
            group_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, client_id: i64, group_id: i64) -> Result<Client, DomainError> {
        let group = self
            .group_repo
            .get_by_id(group_id)
            .await?
            .ok_or(DomainError::GroupNotFound(group_id))?;

        let _client = self
            .client_repo
            .get_by_id(client_id)
            .await?
            .ok_or(DomainError::NotFound(format!(
                "Client {} not found",
                client_id
            )))?;

        if !group.enabled {
            warn!(
                client_id = client_id,
                group_id = group_id,
                group_name = %group.name,
                "Assigning client to disabled group"
            );
        }

        self.client_repo.assign_group(client_id, group_id).await?;

        let updated_client =
            self.client_repo
                .get_by_id(client_id)
                .await?
                .ok_or(DomainError::NotFound(format!(
                    "Client {} not found after update",
                    client_id
                )))?;

        info!(
            client_id = client_id,
            group_id = group_id,
            group_name = %group.name,
            "Client assigned to group successfully"
        );

        if let Err(e) = self.block_filter_engine.load_client_groups().await {
            error!(error = %e, "Failed to reload client groups after group assignment");
        }

        Ok(updated_client)
    }
}
