use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::{PasswordHasher, SessionRepository, UserProvider};
use ferrous_dns_domain::{DomainError, User};

/// Changes the password for an existing user (requires current password) and
/// signs out the user's other sessions.
pub struct ChangePasswordUseCase {
    user_provider: Arc<dyn UserProvider>,
    password_hasher: Arc<dyn PasswordHasher>,
    session_repo: Arc<dyn SessionRepository>,
}

impl ChangePasswordUseCase {
    pub fn new(
        user_provider: Arc<dyn UserProvider>,
        password_hasher: Arc<dyn PasswordHasher>,
        session_repo: Arc<dyn SessionRepository>,
    ) -> Self {
        Self {
            user_provider,
            password_hasher,
            session_repo,
        }
    }

    /// `current_session_id` is the handle (`session.id`) of the caller's own
    /// session, which stays signed in.
    #[instrument(skip(self, current_session_id, current_password, new_password))]
    pub async fn execute(
        &self,
        username: &str,
        current_session_id: &str,
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
            .verify(current_password, &user.password_hash)
            .await?;

        if !valid {
            return Err(DomainError::InvalidCredentials);
        }

        User::validate_password(new_password).map_err(DomainError::InvalidPassword)?;

        let new_hash = self.password_hasher.hash(new_password).await?;
        self.user_provider
            .update_password(username, &new_hash)
            .await?;

        // A leaked password may already back other sessions; the change must end them.
        let revoked = self
            .session_repo
            .delete_other_sessions(username, current_session_id)
            .await?;

        info!(
            username = username,
            revoked_sessions = revoked,
            "Password changed"
        );
        Ok(())
    }
}
