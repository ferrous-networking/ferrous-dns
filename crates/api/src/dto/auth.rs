use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub remember_me: bool,
}

/// Login / MFA-verify result.
///
/// On a completed login `mfa_required` is `false` and `username`/`role`/
/// `expires_at` are set (a session cookie was issued). When a second factor is
/// enrolled, `mfa_required` is `true` and `challenge_token`/`methods` are set
/// instead (no cookie yet).
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct LoginResponse {
    pub mfa_required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_token: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<String>,
}

/// Second step of MFA login: verify a TOTP or recovery code against a challenge.
#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyMfaRequest {
    pub challenge_token: String,
    /// A 6-digit TOTP code or a recovery code.
    pub code: String,
}

/// TOTP enrollment material (returned by `/auth/2fa/setup`).
#[derive(Debug, Serialize, ToSchema)]
pub struct SetupTotpResponse {
    /// base32 secret for manual entry.
    pub secret: String,
    /// `otpauth://` provisioning URI.
    pub otpauth_uri: String,
    /// Inline SVG QR code for the provisioning URI.
    pub qr_svg: String,
}

/// Confirms TOTP enrollment with the first generated code.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ConfirmTotpRequest {
    pub code: String,
}

/// One-time recovery codes, shown once after enrollment.
#[derive(Debug, Serialize, ToSchema)]
pub struct RecoveryCodesResponse {
    pub recovery_codes: Vec<String>,
}

/// Disables all second factors after re-verifying the password.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DisableMfaRequest {
    pub password: String,
}

/// A registered passkey, summarized for the settings UI.
#[derive(Debug, Serialize, ToSchema)]
pub struct PasskeyResponse {
    pub id: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

/// A user's second-factor enrollment status.
#[derive(Debug, Serialize, ToSchema)]
pub struct MfaStatusResponse {
    pub totp_enabled: bool,
    pub recovery_codes_remaining: usize,
    pub webauthn_configured: bool,
    pub passkeys: Vec<PasskeyResponse>,
}

/// Begins passkey registration (optionally naming the credential).
#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct RegisterPasskeyStartRequest {
    #[serde(default)]
    pub label: Option<String>,
}

/// Server-side challenge plus the ceremony token to echo back.
#[derive(Debug, Serialize, ToSchema)]
pub struct WebauthnRegisterStartResponse {
    /// Opaque ceremony token (return it in the finish request).
    pub ceremony_token: String,
    /// `CreationChallengeResponse` JSON for `navigator.credentials.create`.
    #[schema(value_type = Object)]
    pub challenge: serde_json::Value,
}

/// Completes passkey registration.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterPasskeyFinishRequest {
    pub ceremony_token: String,
    #[serde(default)]
    pub label: Option<String>,
    /// `RegisterPublicKeyCredential` JSON from the browser.
    #[schema(value_type = Object)]
    pub response: serde_json::Value,
}

/// Begins a passkey login for a pending MFA challenge.
#[derive(Debug, Deserialize, ToSchema)]
pub struct WebauthnAuthStartRequest {
    pub challenge_token: String,
}

/// Completes a passkey login.
#[derive(Debug, Deserialize, ToSchema)]
pub struct WebauthnAuthFinishRequest {
    pub challenge_token: String,
    /// `PublicKeyCredential` JSON from the browser.
    #[schema(value_type = Object)]
    pub response: serde_json::Value,
}

/// Server-side challenge plus the ceremony token, for usernameless login.
#[derive(Debug, Serialize, ToSchema)]
pub struct DiscoverableStartResponse {
    /// Opaque ceremony token (return it in the finish request).
    pub challenge_token: String,
    /// `RequestChallengeResponse` JSON for `navigator.credentials.get`
    /// (empty `allowCredentials` — the authenticator offers resident passkeys).
    #[schema(value_type = Object)]
    pub challenge: serde_json::Value,
}

/// Completes a usernameless (passwordless) passkey login.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DiscoverableFinishRequest {
    pub challenge_token: String,
    /// `PublicKeyCredential` JSON from the browser.
    #[schema(value_type = Object)]
    pub response: serde_json::Value,
    #[serde(default)]
    pub remember_me: bool,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct SetupPasswordRequest {
    pub password: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthStatusResponse {
    pub enabled: bool,
    pub setup_required: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SessionResponse {
    pub id: String,
    pub username: String,
    pub role: String,
    pub ip_address: String,
    pub user_agent: String,
    pub remember_me: bool,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
}
