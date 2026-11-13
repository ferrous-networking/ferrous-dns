use std::sync::Arc;
use tracing::{info, instrument};

use super::session_factory::session_handle;
use crate::ports::SessionRepository;
use ferrous_dns_domain::DomainError;

/// Ends a session named by the handle the session list shows (`session.id`
/// of a stored session), or by its token.
pub struct RevokeSessionUseCase {
    session_repo: Arc<dyn SessionRepository>,
}

impl RevokeSessionUseCase {
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self { session_repo }
    }

    /// A handle names its row directly; a token names the row stored under its
    /// hash. Deleting both covers either without telling them apart.
    #[instrument(skip_all)]
    pub async fn execute(&self, handle_or_token: &str) -> Result<(), DomainError> {
        self.session_repo.delete(handle_or_token).await?;
        self.session_repo
            .delete(&session_handle(handle_or_token))
            .await?;
        info!("Session revoked");
        Ok(())
    }
}
