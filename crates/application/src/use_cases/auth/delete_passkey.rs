use std::sync::Arc;

use tracing::{info, instrument};

use crate::ports::MfaRepository;
use ferrous_dns_domain::DomainError;

/// Removes a single registered passkey belonging to the given user.
pub struct DeletePasskeyUseCase {
    mfa_repo: Arc<dyn MfaRepository>,
}

impl DeletePasskeyUseCase {
    pub fn new(mfa_repo: Arc<dyn MfaRepository>) -> Self {
        Self { mfa_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, username: &str, id: i64) -> Result<(), DomainError> {
        self.mfa_repo.delete_credential(id, username).await?;
        info!(username = username, passkey_id = id, "Passkey removed");
        Ok(())
    }
}
