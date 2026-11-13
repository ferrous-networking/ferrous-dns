use std::sync::Arc;
use tracing::{info, instrument};

use super::session_factory::session_handle;
use crate::ports::SessionRepository;
use ferrous_dns_domain::DomainError;

/// Destroys the session a cookie or Pi-hole sid carries (logout).
pub struct LogoutUseCase {
    session_repo: Arc<dyn SessionRepository>,
}

impl LogoutUseCase {
    pub fn new(session_repo: Arc<dyn SessionRepository>) -> Self {
        Self { session_repo }
    }

    /// `token` is the session's token, never its handle: see [`super::RevokeSessionUseCase`].
    #[instrument(skip_all)]
    pub async fn execute(&self, token: &str) -> Result<(), DomainError> {
        self.session_repo.delete(&session_handle(token)).await?;
        info!("Session revoked");
        Ok(())
    }
}
