use std::sync::Arc;

use ferrous_dns_domain::{AdminConfig, User, UserRole, UserSource};

/// Reads the admin user from TOML config (`[auth.admin]`).
///
/// This is the "escape hatch" — if a user loses access to the database,
/// they can always edit the TOML file and restart to regain admin access.
pub struct TomlAdminProvider {
    admin_config: AdminConfig,
}

impl TomlAdminProvider {
    pub fn new(admin_config: AdminConfig) -> Self {
        Self { admin_config }
    }

    /// Returns the TOML admin as a `User` entity, or `None` if no password is set.
    pub fn get_admin(&self) -> Option<User> {
        let hash = self.admin_config.password_hash.as_deref()?;
        if hash.is_empty() {
            return None;
        }

        Some(User {
            id: None,
            username: Arc::from(self.admin_config.username.as_str()),
            display_name: None,
            password_hash: Arc::from(hash),
            role: UserRole::Admin,
            source: UserSource::Toml,
            enabled: true,
            created_at: None,
            updated_at: None,
        })
    }

    /// Returns the admin username regardless of password state.
    pub fn admin_username(&self) -> &str {
        &self.admin_config.username
    }
}
