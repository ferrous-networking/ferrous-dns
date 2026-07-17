use ferrous_dns_domain::DomainError;

/// A newly registered credential, ready to persist.
pub struct RegisteredCredential {
    /// base64url credential id.
    pub credential_id: String,
    /// Serialized webauthn-rs `Passkey` (JSON).
    pub passkey_json: String,
    pub sign_count: i64,
}

/// Outcome of a successful authentication ceremony.
pub struct AuthenticatedCredential {
    /// base64url credential id that signed the assertion.
    pub credential_id: String,
    /// Updated signature counter (for clone detection).
    pub sign_count: i64,
}

/// Port abstracting the WebAuthn ceremonies (register/authenticate).
///
/// The boundary speaks JSON (`serde_json::Value` for the browser-facing
/// challenge/response, opaque strings for the server-side ceremony state and
/// stored `Passkey`s) so the application layer never depends on `webauthn-rs`.
pub trait WebauthnService: Send + Sync {
    /// Whether WebAuthn is configured (`[auth.webauthn]` populated).
    fn is_configured(&self) -> bool;

    /// Begin registration. `existing_passkeys` are the user's already-registered
    /// serialized `Passkey`s, excluded to prevent double-enrollment. Returns the
    /// challenge to send to the browser and the opaque ceremony state to persist.
    fn start_registration(
        &self,
        username: &str,
        display_name: &str,
        existing_passkeys: &[String],
    ) -> Result<(serde_json::Value, String), DomainError>;

    /// Complete registration from the browser response and stored state.
    fn finish_registration(
        &self,
        response: serde_json::Value,
        state_json: &str,
    ) -> Result<RegisteredCredential, DomainError>;

    /// Begin authentication against the user's stored `Passkey`s (JSON).
    fn start_authentication(
        &self,
        passkeys_json: &[String],
    ) -> Result<(serde_json::Value, String), DomainError>;

    /// Complete authentication from the browser response and stored state.
    fn finish_authentication(
        &self,
        response: serde_json::Value,
        state_json: &str,
    ) -> Result<AuthenticatedCredential, DomainError>;

    /// Begin a usernameless (discoverable-credential) authentication. No user is
    /// known yet: returns a challenge with empty `allowCredentials` and the
    /// opaque ceremony state to persist.
    fn start_discoverable(&self) -> Result<(serde_json::Value, String), DomainError>;

    /// Extract the base64url credential id from a discoverable assertion so the
    /// caller can look up which user (and stored `Passkey`) it belongs to.
    fn identify_discoverable(&self, response: serde_json::Value) -> Result<String, DomainError>;

    /// Complete a discoverable authentication against the resolved user's stored
    /// `Passkey` (JSON) and the persisted ceremony state.
    fn finish_discoverable(
        &self,
        response: serde_json::Value,
        state_json: &str,
        passkey_json: &str,
    ) -> Result<AuthenticatedCredential, DomainError>;
}
