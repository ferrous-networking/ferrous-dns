use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::UserRepository;
use ferrous_dns_domain::DomainError;

/// Deletes a database user. TOML admin cannot be deleted.
pub struct DeleteUserUseCase {
    user_repo: Arc<dyn UserRepository>,
}

impl DeleteUserUseCase {
    pub fn new(user_repo: Arc<dyn UserRepository>) -> Self {
        Self { user_repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, id: i64) -> Result<(), DomainError> {
        let user = self
            .user_repo
            .get_by_id(id)
            .await?
            .ok_or(DomainError::UserNotFound(id.to_string()))?;

        if user.is_protected() {
            return Err(DomainError::ProtectedUser);
        }

        self.user_repo.delete(id).await?;

        info!(username = %user.username, "User deleted");
        Ok(())
    }
}
