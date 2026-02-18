use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ClientSubnetRepository;

pub struct DeleteClientSubnetUseCase {
    subnet_repo: Arc<dyn ClientSubnetRepository>,
}

impl DeleteClientSubnetUseCase {
    pub fn new(subnet_repo: Arc<dyn ClientSubnetRepository>) -> Self {
        Self { subnet_repo }
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

        Ok(())
    }
}
