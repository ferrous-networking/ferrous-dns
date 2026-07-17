use std::sync::Arc;

use tracing::{info, instrument, warn};

use crate::ports::{MfaRepository, PasswordHasher, UserProvider};
use ferrous_dns_domain::DomainError;

/// Disables all second factors for a user after re-verifying their password.
///
/// Removes TOTP, recovery codes, and any registered passkeys.
pub struct DisableMfaUseCase {
    user_provider: Arc<dyn UserProvider>,
    password_hasher: Arc<dyn PasswordHasher>,
    mfa_repo: Arc<dyn MfaRepository>,
}

impl DisableMfaUseCase {
    pub fn new(
        user_provider: Arc<dyn UserProvider>,
        password_hasher: Arc<dyn PasswordHasher>,
        mfa_repo: Arc<dyn MfaRepository>,
    ) -> Self {
        Self {
            user_provider,
            password_hasher,
            mfa_repo,
        }
    }

    #[instrument(skip(self, password))]
    pub async fn execute(&self, username: &str, password: &str) -> Result<(), DomainError> {
        let user = self
            .user_provider
            .get_by_username(username)
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

        if !self.password_hasher.verify(password, &user.password_hash)? {
            warn!(username = username, "Failed MFA disable (bad password)");
            return Err(DomainError::InvalidCredentials);
        }

        self.mfa_repo.delete_all(username).await?;

        info!(username = username, "Two-factor authentication disabled");
        Ok(())
    }
}
