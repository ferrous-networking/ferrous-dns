use async_trait::async_trait;
use ferrous_dns_domain::{ApiToken, DomainError};

/// A token key as persisted: display prefix and the SHA-256 hash used for lookup.
pub struct ApiKeyMaterial<'a> {
    pub prefix: &'a str,
    pub hash: &'a str,
}

/// Port for managing named API tokens in persistent storage.
///
/// Tokens are validated via SHA-256 hashes; the raw key is never stored.
#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    /// Store a new token (name + prefix + hash). Returns the persisted entity.
    async fn create(
        &self,
        name: &str,
        key_prefix: &str,
        key_hash: &str,
    ) -> Result<ApiToken, DomainError>;

    /// List all tokens (only prefix and metadata).
    async fn get_all(&self) -> Result<Vec<ApiToken>, DomainError>;

    async fn get_by_id(&self, id: i64) -> Result<Option<ApiToken>, DomainError>;

    /// Find a token by name (for duplicate detection).
    async fn get_by_name(&self, name: &str) -> Result<Option<ApiToken>, DomainError>;

    /// Update a token's name and, when `new_key` is given, replace its key.
    async fn update(
        &self,
        id: i64,
        name: &str,
        new_key: Option<ApiKeyMaterial<'_>>,
    ) -> Result<ApiToken, DomainError>;

    /// Delete a token by ID (revocation).
    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    /// Update the `last_used_at` timestamp when a token is used for auth.
    async fn update_last_used(&self, id: i64) -> Result<(), DomainError>;

    /// Find a token ID by its SHA-256 hash (indexed lookup).
    async fn get_id_by_hash(&self, key_hash: &str) -> Result<Option<i64>, DomainError>;
}
