use std::sync::Arc;
use tracing::instrument;

use crate::ports::UserProvider;
use ferrous_dns_domain::{DomainError, User};

/// Lists all users from all sources (TOML admin + database users).
pub struct GetUsersUseCase {
    user_provider: Arc<dyn UserProvider>,
}

impl GetUsersUseCase {
    pub fn new(user_provider: Arc<dyn UserProvider>) -> Self {
        Self { user_provider }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self) -> Result<Vec<User>, DomainError> {
        self.user_provider.get_all().await
    }
}
