use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::{info, instrument};

use ferrous_dns_application::ports::{ConfigFilePersistence, UserProvider, UserRepository};
use ferrous_dns_domain::{Config, DomainError, User};

use super::toml_admin_provider::TomlAdminProvider;

/// Combines TOML admin source with SQLite user repository.
///
/// Follows the same Composite pattern as `CompositeServiceCatalog`:
/// a static source (TOML admin) merged with a dynamic source (SQLite users).
/// TOML admin always takes priority when usernames collide.
///
/// Shares the same `Arc<RwLock<Config>>` as the rest of the application
/// so that password changes are immediately visible to `GetAuthStatusUseCase`.
pub struct CompositeUserProvider {
    toml_admin: RwLock<TomlAdminProvider>,
    db_users: Arc<dyn UserRepository>,
    config: Arc<RwLock<Config>>,
    config_path: Option<String>,
    config_persistence: Arc<dyn ConfigFilePersistence>,
}

impl CompositeUserProvider {
    pub fn new(
        toml_admin: TomlAdminProvider,
        db_users: Arc<dyn UserRepository>,
        config: Arc<RwLock<Config>>,
        config_path: Option<String>,
        config_persistence: Arc<dyn ConfigFilePersistence>,
    ) -> Self {
        Self {
            toml_admin: RwLock::new(toml_admin),
            db_users,
            config,
            config_path,
            config_persistence,
        }
    }
}

#[async_trait]
impl UserProvider for CompositeUserProvider {
    #[instrument(skip(self))]
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        let admin = self.toml_admin.read().await;
        if admin.admin_username() == username {
            return Ok(admin.get_admin());
        }
        drop(admin);

        self.db_users.get_by_username(username).await
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        let mut users = Vec::new();

        let admin = self.toml_admin.read().await;
        if let Some(admin_user) = admin.get_admin() {
            users.push(admin_user);
        }
        drop(admin);

        let db_users = self.db_users.get_all().await?;
        users.extend(db_users);

        Ok(users)
    }

    #[instrument(skip(self, password_hash))]
    async fn update_password(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<(), DomainError> {
        let admin = self.toml_admin.read().await;
        let is_toml_admin = admin.admin_username() == username;
        drop(admin);

        if is_toml_admin {
            return self.update_toml_admin_password(password_hash).await;
        }

        let user = self
            .db_users
            .get_by_username(username)
            .await?
            .ok_or_else(|| DomainError::UserNotFound(username.to_string()))?;

        let id = user
            .id
            .ok_or_else(|| DomainError::UserNotFound(username.to_string()))?;

        self.db_users.update_password(id, password_hash).await
    }
}

impl CompositeUserProvider {
    async fn update_toml_admin_password(&self, password_hash: &str) -> Result<(), DomainError> {
        let mut config = self.config.write().await;
        config.auth.admin.password_hash = Some(password_hash.to_string());

        if let Some(ref path) = self.config_path {
            self.config_persistence
                .save_config_to_file(&config, path)
                .map_err(|e| DomainError::ConfigError(format!("Failed to save config: {e}")))?;
        }

        let admin_config = config.auth.admin.clone();
        drop(config);

        let mut admin = self.toml_admin.write().await;
        *admin = TomlAdminProvider::new(admin_config);

        info!("TOML admin password updated");
        Ok(())
    }
}
