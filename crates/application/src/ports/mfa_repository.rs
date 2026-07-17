use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, MfaChallenge, RecoveryCode, UserMfa, WebauthnCredential};

/// Port for persisting multi-factor state: TOTP enrollment, single-use
/// recovery codes, short-lived login challenges, and WebAuthn credentials.
///
/// Everything is keyed by username so it covers both the TOML admin and
/// database users.
#[async_trait]
pub trait MfaRepository: Send + Sync {
    // --- TOTP enrollment ---

    /// Fetch the MFA record for a user, if any.
    async fn get(&self, username: &str) -> Result<Option<UserMfa>, DomainError>;

    /// Create or replace the (unconfirmed) TOTP secret for a user.
    async fn upsert_secret(&self, username: &str, secret: &str) -> Result<(), DomainError>;

    /// Mark TOTP enabled after the first code is confirmed.
    async fn enable(&self, username: &str) -> Result<(), DomainError>;

    /// Remove all MFA state for a user (TOTP, recovery codes, WebAuthn creds).
    async fn delete_all(&self, username: &str) -> Result<(), DomainError>;

    // --- Recovery codes ---

    /// Replace the full set of recovery codes with the given hashes.
    async fn replace_recovery_codes(
        &self,
        username: &str,
        code_hashes: &[String],
    ) -> Result<(), DomainError>;

    /// List a user's unused recovery codes.
    async fn list_unused_recovery_codes(
        &self,
        username: &str,
    ) -> Result<Vec<RecoveryCode>, DomainError>;

    /// Mark a recovery code consumed.
    async fn mark_recovery_code_used(&self, id: i64) -> Result<(), DomainError>;

    // --- Login challenges ---

    async fn create_challenge(&self, challenge: &MfaChallenge) -> Result<(), DomainError>;
    async fn get_challenge(&self, token: &str) -> Result<Option<MfaChallenge>, DomainError>;
    async fn delete_challenge(&self, token: &str) -> Result<(), DomainError>;
    /// Remove challenges past their expiry. Returns the number removed.
    async fn delete_expired_challenges(&self) -> Result<u64, DomainError>;

    // --- WebAuthn credentials ---

    async fn add_credential(&self, cred: &WebauthnCredential) -> Result<(), DomainError>;
    async fn list_credentials(
        &self,
        username: &str,
    ) -> Result<Vec<WebauthnCredential>, DomainError>;
    /// Look up a single credential by its (unique) base64url credential id.
    /// Used by usernameless/discoverable passkey login to resolve the owner.
    async fn find_credential_by_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<WebauthnCredential>, DomainError>;
    async fn update_credential_counter(
        &self,
        credential_id: &str,
        sign_count: i64,
    ) -> Result<(), DomainError>;
    async fn delete_credential(&self, id: i64, username: &str) -> Result<(), DomainError>;
    async fn has_credentials(&self, username: &str) -> Result<bool, DomainError>;
}
