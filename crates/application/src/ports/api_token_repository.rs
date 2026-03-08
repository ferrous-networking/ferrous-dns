use async_trait::async_trait;
use ferrous_dns_domain::{ApiToken, DomainError};

/// Port for managing named API tokens in persistent storage.
///
/// Tokens are validated via SHA-256 hashes. The raw token is also persisted
/// for admin display but never exposed in listing endpoints.
#[async_trait]
pub trait ApiTokenRepository: Send + Sync {
    /// Store a new token (name + hash + prefix + raw). Returns the persisted entity.
    async fn create(
        &self,
        name: &str,
        key_prefix: &str,
        key_hash: &str,
        key_raw: &str,
    ) -> Result<ApiToken, DomainError>;

    /// List all tokens (without raw keys — only prefix and metadata).
    async fn get_all(&self) -> Result<Vec<ApiToken>, DomainError>;

    /// Find a token by database ID.
    async fn get_by_id(&self, id: i64) -> Result<Option<ApiToken>, DomainError>;

    /// Find a token by name (for duplicate detection).
    async fn get_by_name(&self, name: &str) -> Result<Option<ApiToken>, DomainError>;

    /// Update a token's name and optionally its key.
    async fn update(
        &self,
        id: i64,
        name: &str,
        key_prefix: Option<&str>,
        key_hash: Option<&str>,
        key_raw: Option<&str>,
    ) -> Result<ApiToken, DomainError>;

    /// Delete a token by ID (revocation).
    async fn delete(&self, id: i64) -> Result<(), DomainError>;

    /// Update the `last_used_at` timestamp when a token is used for auth.
    async fn update_last_used(&self, id: i64) -> Result<(), DomainError>;

    /// Get all token hashes for validation lookup.
    /// Returns `(id, key_hash)` pairs for efficient matching.
    async fn get_all_hashes(&self) -> Result<Vec<(i64, String)>, DomainError>;

    /// Find a token ID by its SHA-256 hash (indexed lookup).
    async fn get_id_by_hash(&self, key_hash: &str) -> Result<Option<i64>, DomainError>;
}
