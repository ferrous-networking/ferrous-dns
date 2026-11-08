use crate::ports::{BlockFilterEnginePort, DohIdRepository};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{error, info, instrument};

pub struct DeleteDohIdUseCase {
    doh_id_repo: Arc<dyn DohIdRepository>,
    block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl DeleteDohIdUseCase {
    pub fn new(
        doh_id_repo: Arc<dyn DohIdRepository>,
        block_filter_engine: Arc<dyn BlockFilterEnginePort>,
    ) -> Self {
        Self {
            doh_id_repo,
            block_filter_engine,
        }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        let doh_id = self
            .doh_id_repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::DohIdNotFound(id))?;

        self.doh_id_repo.delete(id).await?;

        info!(
            doh_id = id,
            name = %doh_id.name,
            client_id = %doh_id.client_id,
            "DoH ID deleted successfully"
        );

        if let Err(e) = self.block_filter_engine.load_client_groups().await {
            error!(error = %e, "Failed to reload client groups after DoH ID deletion");
        }

        Ok(())
    }
}
