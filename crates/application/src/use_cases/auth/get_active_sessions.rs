use std::sync::Arc;
use tracing::instrument;

use crate::ports::SessionRepository;
use ferrous_dns_domain::{AuthSession, DomainError};

/// Lists all active (non-expired) browser sessions.
pub struct GetActiveSessionsUseCase {
    session_repo: Arc<dyn SessionRepository>,
}

impl GetActiveSessionsUseCase {
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self { session_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self) -> Result<Vec<AuthSession>, DomainError> {
        self.session_repo.get_all_active().await
    }
}
