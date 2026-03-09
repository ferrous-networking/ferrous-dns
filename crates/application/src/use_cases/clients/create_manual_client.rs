use ferrous_dns_domain::{Client, DomainError};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, ClientRepository, GroupRepository};

pub struct CreateManualClientUseCase {
    client_repo: Arc<dyn ClientRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Option<Arc<dyn BlockFilterEnginePort>>,
}

impl CreateManualClientUseCase {
    pub fn new(
        client_repo: Arc<dyn ClientRepository>,
        group_repo: Arc<dyn GroupRepository>,
    ) -> Self {
        Self {
            client_repo,
            group_repo,
            block_filter_engine: None,
        }
    }

    pub fn with_block_filter(mut self, engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        self.block_filter_engine = Some(engine);
        self
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
                .ok_or(DomainError::GroupNotFound(gid))?;
        }

        let initial = self.client_repo.get_or_create(ip_address).await?;

        if let Some(hostname) = hostname {
            self.client_repo
                .update_hostname(ip_address, hostname)
                .await?;
        }

        if let Some(mac) = mac_address {
            self.client_repo.update_mac_address(ip_address, mac).await?;
        }

        let group_assigned = group_id.is_some();
        if let (Some(client_id), Some(gid)) = (initial.id, group_id) {
            self.client_repo.assign_group(client_id, gid).await?;
        }

        let client = self.client_repo.get_or_create(ip_address).await?;

        info!(
            ip = %ip_address,
            group_id = ?group_id,
            "Manual client created successfully"
        );

        if group_assigned {
            if let Some(ref engine) = self.block_filter_engine {
                if let Err(e) = engine.load_client_groups().await {
                    error!(error = %e, "Failed to reload client groups after manual client creation");
                }
            }
        }

        Ok(client)
    }
}
