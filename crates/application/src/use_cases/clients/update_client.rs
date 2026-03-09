use ferrous_dns_domain::{Client, DomainError};
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, ClientRepository, GroupRepository};

pub struct UpdateClientUseCase {
    client_repo: Arc<dyn ClientRepository>,
    group_repo: Option<Arc<dyn GroupRepository>>,
    block_filter_engine: Option<Arc<dyn BlockFilterEnginePort>>,
}

impl UpdateClientUseCase {
    pub fn new(client_repo: Arc<dyn ClientRepository>) -> Self {
        Self {
            client_repo,
            group_repo: None,
            block_filter_engine: None,
        }
    }

    pub fn with_block_filter(mut self, engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        self.block_filter_engine = Some(engine);
        self
    }

    pub fn with_group_repo(mut self, repo: Arc<dyn GroupRepository>) -> Self {
        self.group_repo = Some(repo);
        self
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

        if let Some(ref h) = hostname {
            self.client_repo
                .update_hostname(client.ip_address, h.clone())
                .await?;
        }

        let group_changed = group_id.is_some_and(|gid| client.group_id != Some(gid));

        if let Some(gid) = group_id {
            if let Some(ref group_repo) = self.group_repo {
                group_repo
                    .get_by_id(gid)
                    .await?
                    .ok_or(DomainError::GroupNotFound(gid))?;
            }
            self.client_repo.assign_group(client_id, gid).await?;
        }

        let updated = self
            .client_repo
            .get_by_id(client_id)
            .await?
            .ok_or(DomainError::ClientNotFound(client_id.to_string()))?;

        info!(client_id, hostname = ?hostname, group_id = ?group_id, "Client updated");

        if group_changed {
            if let Some(ref engine) = self.block_filter_engine {
                if let Err(e) = engine.load_client_groups().await {
                    error!(error = %e, "Failed to reload client groups after client update");
                }
            }
        }

        Ok(updated)
    }
}
