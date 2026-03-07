use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, ClientSubnetRepository};

pub struct DeleteClientSubnetUseCase {
    subnet_repo: Arc<dyn ClientSubnetRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl DeleteClientSubnetUseCase {
    pub fn new(
        subnet_repo: Arc<dyn ClientSubnetRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            subnet_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        let subnet = self
            .subnet_repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::SubnetNotFound(format!(
                "Subnet {} not found",
                id
            )))?;

        self.subnet_repo.delete(id).await?;

        info!(
            subnet_id = id,
            cidr = %subnet.subnet_cidr,
            "Client subnet deleted successfully"
        );

        if let Err(e) = self.block_filter_engine.load_client_groups().await {
            error!(error = %e, "Failed to reload client groups after subnet deletion");
        }

        Ok(())
    }
}
