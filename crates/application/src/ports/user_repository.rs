use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, User};
use std::sync::Arc;

/// Port for managing database-stored user accounts.
///
/// The TOML admin is NOT managed through this port — it comes from
/// `Config.auth.admin` and is combined via the `UserProvider` port.
#[async_trait]
pub trait UserRepository: Send + Sync {
    /// Create a new user in the database.
    async fn create(
        &self,
        username: &str,
        display_name: Option<&str>,
        password_hash: &str,
        role: &str,
    ) -> Result<User, DomainError>;

    /// Find a user by username. Returns `None` if not found.
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError>;

    /// Find a user by database ID. Returns `None` if not found.
    async fn get_by_id(&self, id: i64) -> Result<Option<User>, DomainError>;

    /// List all database users.
    async fn get_all(&self) -> Result<Vec<User>, DomainError>;

    /// Update a user's password hash.
    async fn update_password(&self, id: i64, password_hash: &str) -> Result<(), DomainError>;

    /// Delete a user by ID.
    async fn delete(&self, id: i64) -> Result<(), DomainError>;
}

/// Composite port that combines TOML admin + database users.
///
/// Follows the same Composite pattern as `CompositeServiceCatalog`:
/// a static source (TOML config) merged with a dynamic source (SQLite).
/// TOML admin always takes priority when usernames collide.
#[async_trait]
pub trait UserProvider: Send + Sync {
    /// Find a user by username across all sources (TOML first, then DB).
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError>;

    /// List all users from all sources.
    async fn get_all(&self) -> Result<Vec<User>, DomainError>;

    /// Update password for any user source.
    /// For TOML admin: persists hash to config file.
    /// For DB users: updates the `users` table.
    async fn update_password(&self, username: &str, password_hash: &str)
        -> Result<(), DomainError>;
}

/// Port for hashing and verifying passwords with Argon2id.
///
/// Implementations must offload CPU-intensive hashing to a blocking thread
/// (`tokio::task::spawn_blocking`) to avoid starving the async runtime.
pub trait PasswordHasher: Send + Sync {
    /// Hash a plaintext password. Returns the full Argon2id PHC string.
    fn hash(&self, password: &str) -> Result<String, DomainError>;

    /// Verify a plaintext password against a stored hash.
    fn verify(&self, password: &str, hash: &str) -> Result<bool, DomainError>;
}

/// Input for creating a new database user via use case.
pub struct CreateUserInput {
    pub username: Arc<str>,
    pub display_name: Option<Arc<str>>,
    pub password: String,
    pub role: String,
}
