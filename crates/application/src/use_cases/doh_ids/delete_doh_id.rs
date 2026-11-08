use crate::ports::DohIdRepository;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{info, instrument};

pub struct DeleteDohIdUseCase {
    doh_id_repo: Arc<dyn DohIdRepository>,
}

impl DeleteDohIdUseCase {
    pub fn new(doh_id_repo: Arc<dyn DohIdRepository>) -> Self {
        Self { doh_id_repo }
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

        Ok(())
    }
}
