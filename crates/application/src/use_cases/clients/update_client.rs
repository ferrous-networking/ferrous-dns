use crate::use_cases::groups::require_group;
use ferrous_dns_domain::{Client, DomainError, HostnameSource};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, ClientRepository, GroupRepository};

pub struct UpdateClientUseCase {
    client_repo: Arc<dyn ClientRepository>,
    group_repo: Arc<dyn GroupRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl UpdateClientUseCase {
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
    pub async fn execute(
        &self,
        client_id: i64,
        hostname: Option<String>,
        group_id: Option<i64>,
    ) -> Result<Client, DomainError> {
        let client = self
            .client_repo
            .get_by_id(client_id)
            .await?
            .ok_or(DomainError::ClientNotFound(client_id.to_string()))?;

        // Edit forms send the current name back with every change, so only a
        // different name is one set by hand.
        if let Some(h) = hostname
            .as_ref()
            .filter(|h| client.hostname.as_deref() != Some(h.as_str()))
        {
            self.client_repo
                .update_hostname(client.ip_address, h.clone(), HostnameSource::Manual)
                .await?;
        }

        let group_changed = group_id.is_some_and(|gid| client.group_id != Some(gid));

        if let Some(gid) = group_id {
            require_group(self.group_repo.as_ref(), gid).await?;
            self.client_repo.assign_group(client_id, gid).await?;
        }

        let updated = self
            .client_repo
            .get_by_id(client_id)
            .await?
            .ok_or(DomainError::ClientNotFound(client_id.to_string()))?;

        info!(client_id, hostname = ?hostname, group_id = ?group_id, "Client updated");

        if group_changed {
            if let Err(e) = self.block_filter_engine.load_client_groups().await {
                error!(error = %e, "Failed to reload client groups after client update");
            }
        }

        Ok(updated)
    }
}
