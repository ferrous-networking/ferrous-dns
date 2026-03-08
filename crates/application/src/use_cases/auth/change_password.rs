use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{PasswordHasher, UserProvider};
use ferrous_dns_domain::{DomainError, User};

/// Changes the password for an existing user (requires current password).
pub struct ChangePasswordUseCase {
    user_provider: Arc<dyn UserProvider>,
    password_hasher: Arc<dyn PasswordHasher>,
}

impl ChangePasswordUseCase {
    pub fn new(
        user_provider: Arc<dyn UserProvider>,
        password_hasher: Arc<dyn PasswordHasher>,
    ) -> Self {
        Self {
            user_provider,
            password_hasher,
        }
    }

    #[instrument(skip(self, current_password, new_password))]
    pub async fn execute(
        &self,
        username: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), DomainError> {
        let user = self
            .user_provider
            .get_by_username(username)
            .await?
            .ok_or(DomainError::UserNotFound(username.to_string()))?;

        let valid = self
            .password_hasher
            .verify(current_password, &user.password_hash)?;

        if !valid {
            return Err(DomainError::InvalidCredentials);
        }

        User::validate_password(new_password).map_err(DomainError::InvalidPassword)?;

        let new_hash = self.password_hasher.hash(new_password)?;
        self.user_provider
            .update_password(username, &new_hash)
            .await?;

        info!(username = username, "Password changed");
        Ok(())
    }
}
