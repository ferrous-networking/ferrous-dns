use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::SessionRepository;
use ferrous_dns_domain::DomainError;

/// Destroys a browser session (logout).
pub struct LogoutUseCase {
    session_repo: Arc<dyn SessionRepository>,
}

impl LogoutUseCase {
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self { session_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, session_id: &str) -> Result<(), DomainError> {
        self.session_repo.delete(session_id).await?;
        info!("Session revoked");
        Ok(())
    }
}
