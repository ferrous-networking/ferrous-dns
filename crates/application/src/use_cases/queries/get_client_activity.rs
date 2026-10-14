use crate::ports::{ClientActivity, ClientActivityRepository};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

pub struct GetClientActivityUseCase {
    repository: Arc<dyn ClientActivityRepository>,
}

impl GetClientActivityUseCase {
    pub fn new(repository: Arc<dyn ClientActivityRepository>) -> Self {
        Self { repository }
    }

    pub async fn execute(
        &self,
        clients: &[String],
        bucket_secs: u32,
        period_hours: f32,
    ) -> Result<Vec<ClientActivity>, DomainError> {
        if bucket_secs == 0 {
            return Err(DomainError::InvalidInput(
                "bucket width must be positive".to_string(),
            ));
        }
        self.repository
            .get_client_activity(clients, bucket_secs, period_hours)
            .await
    }
}
