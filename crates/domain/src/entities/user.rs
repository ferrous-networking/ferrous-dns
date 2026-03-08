use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Source of a user account: TOML config file or SQLite database.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserSource {
    /// Admin defined in `ferrous-dns.toml` — always recoverable via file edit.
    Toml,
    /// User stored in SQLite `users` table — managed via API.
    Database,
}

/// Role assigned to a user, controlling access level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    /// Full access: read, write, manage users and tokens.
    Admin,
    /// Read-only: dashboard, query log, stats. No config changes.
    Viewer,
}

impl UserRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Admin => "admin",
            Self::Viewer => "viewer",
        }
    }

    pub fn parse(s: &str) -> Result<Self, String> {
        match s {
            "admin" => Ok(Self::Admin),
            "viewer" => Ok(Self::Viewer),
            other => Err(format!("Invalid role: {other}")),
        }
    }

    pub fn can_write(&self) -> bool {
        matches!(self, Self::Admin)
    }
}

/// A user account that can authenticate with Ferrous DNS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Option<i64>,
    pub username: Arc<str>,
    pub display_name: Option<Arc<str>>,
    pub password_hash: Arc<str>,
    pub role: UserRole,
    pub source: UserSource,
    pub enabled: bool,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl User {
    pub fn new(
        username: Arc<str>,
        password_hash: Arc<str>,
        role: UserRole,
        source: UserSource,
    ) -> Self {
        Self {
            id: None,
            username,
            display_name: None,
            password_hash,
            role,
            source,
            enabled: true,
            created_at: None,
            updated_at: None,
        }
    }

    /// TOML admin cannot be deleted or disabled via API.
    pub fn is_protected(&self) -> bool {
        self.source == UserSource::Toml
    }

    pub fn validate_username(username: &str) -> Result<(), String> {
        if username.is_empty() {
            return Err("Username cannot be empty".to_string());
        }
        if username.len() > 64 {
            return Err("Username cannot exceed 64 characters".to_string());
        }
        let valid = username
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.');
        if !valid {
            return Err(
                "Username can only contain alphanumeric characters, hyphens, underscores, and dots"
                    .to_string(),
            );
        }
        Ok(())
    }

    pub fn validate_display_name(display_name: &Option<Arc<str>>) -> Result<(), String> {
        if let Some(name) = display_name {
            if name.len() > 100 {
                return Err("Display name cannot exceed 100 characters".to_string());
            }
        }
        Ok(())
    }

    pub fn validate_password(password: &str) -> Result<(), String> {
        if password.len() < 8 {
            return Err("Password must be at least 8 characters".to_string());
        }
        if password.len() > 256 {
            return Err("Password cannot exceed 256 characters".to_string());
        }
        Ok(())
    }
}
