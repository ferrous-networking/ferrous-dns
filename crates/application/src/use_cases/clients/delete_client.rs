use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::ports::{BlockFilterEnginePort, ClientRepository};

pub struct DeleteClientUseCase {
    client_repo: Arc<dyn ClientRepository>,
    block_filter_engine: Option<Arc<dyn BlockFilterEnginePort>>,
}

impl DeleteClientUseCase {
    pub fn new(client_repo: Arc<dyn ClientRepository>) -> Self {
        Self {
            client_repo,
            block_filter_engine: None,
        }
    }

    pub fn with_block_filter(mut self, engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        self.block_filter_engine = Some(engine);
        self
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        let client = self
            .client_repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::ClientNotFound(id.to_string()))?;

        let had_group = client.group_id.is_some();

        self.client_repo.delete(id).await?;

        info!(
            client_id = id,
            ip_address = %client.ip_address,
            "Client deleted successfully"
        );

        if had_group {
            if let Some(ref engine) = self.block_filter_engine {
                if let Err(e) = engine.load_client_groups().await {
                    error!(error = %e, "Failed to reload client groups after client deletion");
                }
            }
        }

        Ok(())
    }
}
