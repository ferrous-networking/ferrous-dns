use std::sync::Arc;

/// TOTP enrollment state for a single user, keyed by username.
///
/// Stored in the `user_mfa` table. Because it is keyed by username it covers
/// both the TOML admin (which has no `users` row) and database users.
#[derive(Debug, Clone)]
pub struct UserMfa {
    pub username: Arc<str>,
    /// base32-encoded TOTP shared secret.
    pub totp_secret: Arc<str>,
    /// `false` while enrollment is pending the first confirmed code.
    pub totp_enabled: bool,
    pub created_at: Option<String>,
    pub confirmed_at: Option<String>,
}

/// A single-use recovery code (stored Argon2id-hashed).
#[derive(Debug, Clone)]
pub struct RecoveryCode {
    pub id: i64,
    pub username: Arc<str>,
    pub code_hash: Arc<str>,
    pub used_at: Option<String>,
}

/// Which second-factor method a challenge expects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MfaMethod {
    Totp,
    Webauthn,
}

impl MfaMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Totp => "totp",
            Self::Webauthn => "webauthn",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "totp" => Some(Self::Totp),
            "webauthn" => Some(Self::Webauthn),
            _ => None,
        }
    }
}

/// A short-lived second-factor challenge issued after a correct password.
///
/// Held in the `mfa_challenges` table (~5 min TTL). It is a hard boundary: a
/// half-authenticated login cannot be mistaken for a real session because no
/// `AuthSession` exists until the second factor succeeds.
#[derive(Debug, Clone)]
pub struct MfaChallenge {
    pub token: Arc<str>,
    pub username: Arc<str>,
    pub remember_me: bool,
    pub kind: MfaMethod,
    /// Serialized WebAuthn ceremony state (JSON); `None` for TOTP.
    pub state: Option<String>,
    pub expires_at: String,
}

/// A registered WebAuthn / passkey credential.
///
/// `passkey` holds the serialized webauthn-rs `Passkey` value.
#[derive(Debug, Clone)]
pub struct WebauthnCredential {
    pub id: Option<i64>,
    pub username: Arc<str>,
    pub credential_id: Arc<str>,
    pub label: Option<Arc<str>>,
    pub passkey: String,
    pub sign_count: i64,
    pub created_at: Option<String>,
    pub last_used_at: Option<String>,
}
