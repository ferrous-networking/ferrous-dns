use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{PasswordHasher, UserProvider};
use ferrous_dns_domain::{DomainError, User};

/// Sets the initial password for the TOML admin on first run.
///
/// This endpoint is only callable when no password hash is configured.
/// After the first setup, it returns `PasswordAlreadyConfigured` error.
pub struct SetupPasswordUseCase {
    user_provider: Arc<dyn UserProvider>,
    password_hasher: Arc<dyn PasswordHasher>,
    admin_username: String,
}

impl SetupPasswordUseCase {
    pub fn new(
        user_provider: Arc<dyn UserProvider>,
        password_hasher: Arc<dyn PasswordHasher>,
        admin_username: String,
    ) -> Self {
        Self {
            user_provider,
            password_hasher,
            admin_username,
        }
    }

    #[instrument(skip(self, password))]
    pub async fn execute(&self, password: &str) -> Result<(), DomainError> {
        let user = self
            .user_provider
            .get_by_username(&self.admin_username)
            .await?;

        if let Some(ref u) = user {
            if !u.password_hash.is_empty() {
                return Err(DomainError::PasswordAlreadyConfigured);
            }
        }

        User::validate_password(password).map_err(DomainError::InvalidPassword)?;

        let hash = self.password_hasher.hash(password)?;
        self.user_provider
            .update_password(&self.admin_username, &hash)
            .await?;

        info!("Admin password configured via setup");
        Ok(())
    }
}
