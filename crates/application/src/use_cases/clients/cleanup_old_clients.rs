use crate::ports::ClientRepository;
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::info;

/// Use case: Clean up old clients (data retention)
/// Should be run daily
pub struct CleanupOldClientsUseCase {
    client_repo: Arc<dyn ClientRepository>,
}

impl CleanupOldClientsUseCase {
    pub fn new(client_repo: Arc<dyn ClientRepository>) -> Self {
        Self { client_repo }
    }

    pub async fn execute(&self, retention_days: u32) -> Result<u64, DomainError> {
        let deleted = self.client_repo.delete_older_than(retention_days).await?;
        info!(deleted, retention_days, "Old clients cleaned up");
        Ok(deleted)
    }
}
