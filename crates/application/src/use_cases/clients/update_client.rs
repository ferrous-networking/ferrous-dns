use ferrous_dns_domain::{Client, DomainError};
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ClientRepository;

pub struct UpdateClientUseCase {
    client_repo: Arc<dyn ClientRepository>,
}

impl UpdateClientUseCase {
    pub fn new(client_repo: Arc<dyn ClientRepository>) -> Self {
        Self { client_repo }
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

        if let Some(gid) = group_id {
            self.client_repo.assign_group(client_id, gid).await?;
        }

        let updated = self
            .client_repo
            .get_by_id(client_id)
            .await?
            .ok_or(DomainError::ClientNotFound(client_id.to_string()))?;

        info!(client_id, hostname = ?hostname, group_id = ?group_id, "Client updated");
        Ok(updated)
    }
}
