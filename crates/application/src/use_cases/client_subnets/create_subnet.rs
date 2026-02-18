use ferrous_dns_domain::{ClientSubnet, DomainError};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{ClientSubnetRepository, GroupRepository};

pub struct CreateClientSubnetUseCase {
    subnet_repo: Arc<dyn ClientSubnetRepository>,
    group_repo: Arc<dyn GroupRepository>,
}

impl CreateClientSubnetUseCase {
    pub fn new(
        subnet_repo: Arc<dyn ClientSubnetRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self {
            subnet_repo,
            group_repo,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        subnet_cidr: String,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError> {
        
        ClientSubnet::validate_cidr(&subnet_cidr).map_err(DomainError::InvalidCidr)?;

        let _network: ipnetwork::IpNetwork = subnet_cidr
            .parse()
            .map_err(|e| DomainError::InvalidCidr(format!("{}", e)))?;

        self.group_repo
            .get_by_id(group_id)
            .await?
            .ok_or(DomainError::GroupNotFound(format!(
                "Group {} not found",
                group_id
            )))?;

        if self.subnet_repo.exists(&subnet_cidr).await? {
            return Err(DomainError::SubnetConflict(format!(
                "Subnet {} already exists",
                subnet_cidr
            )));
        }

        let subnet = self
            .subnet_repo
            .create(subnet_cidr, group_id, comment)
            .await?;

        info!(
            subnet_id = ?subnet.id,
            cidr = %subnet.subnet_cidr,
            group_id = group_id,
            "Client subnet created successfully"
        );

        Ok(subnet)
    }
}
