use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ClientRepository;

pub struct DeleteClientUseCase {
    client_repo: Arc<dyn ClientRepository>,
}

impl DeleteClientUseCase {
    pub fn new(client_repo: Arc<dyn ClientRepository>) -> Self {
        Self { client_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        
        let client = self
            .client_repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::ClientNotFound(format!(
                "Client {} not found",
                id
            )))?;

        self.client_repo.delete(id).await?;

        info!(
            client_id = id,
            ip_address = %client.ip_address,
            "Client deleted successfully"
        );

        Ok(())
    }
}
