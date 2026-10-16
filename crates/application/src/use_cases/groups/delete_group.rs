use super::require_group;
use ferrous_dns_domain::{Config, DomainError};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, GroupRepository};

pub struct DeleteGroupUseCase {
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    config: Arc<RwLock<Config>>,
}

impl DeleteGroupUseCase {
    pub fn new(
        group_repo: Arc<dyn GroupRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
        config: Arc<RwLock<Config>>,
    ) -> Self {
        Self {
            group_repo,
            block_filter_engine,
            config,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        let group = require_group(self.group_repo.as_ref(), id).await?;

        if group.is_default {
            return Err(DomainError::ProtectedGroupCannotBeDeleted);
        }

        let client_count = self.group_repo.count_clients_in_group(id).await?;
        if client_count > 0 {
            return Err(DomainError::GroupHasAssignedClients(client_count));
        }

        // A pool still naming the group could no longer be saved: every pool
        // save rejects a group that does not exist.
        let routing_pool = self
            .config
            .read()
            .await
            .dns
            .pools
            .iter()
            .find(|pool| pool.groups.contains(&id))
            .map(|pool| pool.name.clone());
        if let Some(pool) = routing_pool {
            return Err(DomainError::GroupRoutedByPool(pool));
        }

        self.group_repo.delete(id).await?;

        info!(
            group_id = ?id,
            name = %group.name,
            "Group deleted successfully"
        );

        // The delete cascades to managed domains and client subnets the engine still holds.
        if let Err(e) = self.block_filter_engine.reload().await {
            error!(error = %e, "Failed to reload block filter after group deletion");
        }

        Ok(())
    }
}
