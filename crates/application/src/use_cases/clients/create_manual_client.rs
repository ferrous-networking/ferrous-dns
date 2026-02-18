use ferrous_dns_domain::{Client, DomainError};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{ClientRepository, GroupRepository};

pub struct CreateManualClientUseCase {
    client_repo: Arc<dyn ClientRepository>,
    group_repo: Arc<dyn GroupRepository>,
}

impl CreateManualClientUseCase {
    pub fn new(
        client_repo: Arc<dyn ClientRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self {
            client_repo,
            group_repo,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(
        &self,
        ip_address: IpAddr,
        group_id: Option<i64>,
        hostname: Option<String>,
        mac_address: Option<String>,
    ) -> Result<Client, DomainError> {
        
        if let Some(gid) = group_id {
            self.group_repo
                .get_by_id(gid)
                .await?
                .ok_or(DomainError::GroupNotFound(format!(
                    "Group {} not found",
                    gid
                )))?;
        }

        let mut client = self.client_repo.get_or_create(ip_address).await?;

        if let Some(hostname) = hostname {
            self.client_repo
                .update_hostname(ip_address, hostname)
                .await?;
        }

        if let Some(mac) = mac_address {
            self.client_repo.update_mac_address(ip_address, mac).await?;
        }

        if let (Some(client_id), Some(gid)) = (client.id, group_id) {
            self.client_repo.assign_group(client_id, gid).await?;
            client.group_id = Some(gid);
        }

        info!(
            ip = %ip_address,
            group_id = ?group_id,
            "Manual client created successfully"
        );

        Ok(client)
    }
}
