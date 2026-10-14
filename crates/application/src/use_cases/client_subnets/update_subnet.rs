use crate::use_cases::groups::require_group;
use ferrous_dns_domain::{ClientSubnet, DomainError};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, ClientSubnetRepository, GroupRepository};

pub struct UpdateClientSubnetUseCase {
    subnet_repo: Arc<dyn ClientSubnetRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl UpdateClientSubnetUseCase {
    pub fn new(
        subnet_repo: Arc<dyn ClientSubnetRepository>,
        group_repo: Arc<dyn GroupRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            subnet_repo,
            group_repo,
            block_filter_engine,
        }
    }

    /// Moves the subnet `id` to `group_id` and replaces its comment.
    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        id: i64,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError> {
        require_group(self.group_repo.as_ref(), group_id).await?;

        let subnet = self.subnet_repo.update(id, group_id, comment).await?;

        info!(
            subnet_id = id,
            cidr = %subnet.subnet_cidr,
            group_id,
            "Client subnet updated successfully"
        );

        if let Err(e) = self.block_filter_engine.load_client_groups().await {
            error!(error = %e, "Failed to reload client groups after subnet update");
        }

        Ok(subnet)
    }
}
