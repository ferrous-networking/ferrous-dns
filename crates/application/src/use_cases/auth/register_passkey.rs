use std::sync::Arc;

use tracing::{info, instrument};

use super::session_factory::generate_session_id;
use crate::ports::{MfaRepository, WebauthnService};
use ferrous_dns_domain::{DomainError, MfaChallenge, MfaMethod, WebauthnCredential};

/// Registers a new WebAuthn passkey for an already-authenticated user
/// (two-step ceremony: `start` then `finish`).
pub struct RegisterPasskeyUseCase {
    webauthn: Arc<dyn WebauthnService>,
    mfa_repo: Arc<dyn MfaRepository>,
    /// TTL of a passkey registration ceremony, in seconds.
    challenge_ttl_secs: i64,
}

/// The browser-facing challenge plus the server ceremony token.
pub struct RegistrationStart {
    pub challenge: serde_json::Value,
    pub ceremony_token: String,
}

impl RegisterPasskeyUseCase {
    pub fn new(
        webauthn: Arc<dyn WebauthnService>,
        mfa_repo: Arc<dyn MfaRepository>,
        challenge_ttl_secs: i64,
    ) -> Self {
        Self {
            webauthn,
            mfa_repo,
            challenge_ttl_secs,
        }
    }

    /// Begin registration: returns the creation challenge for
    /// `navigator.credentials.create` and a ceremony token to echo back.
    #[instrument(skip(self))]
    pub async fn start(
        &self,
        username: &str,
        display_name: &str,
    ) -> Result<RegistrationStart, DomainError> {
        if !self.webauthn.is_configured() {
            return Err(DomainError::WebauthnNotConfigured);
        }

        let existing: Vec<String> = self
            .mfa_repo
            .list_credentials(username)
            .await?
            .into_iter()
            .map(|c| c.passkey)
            .collect();

        let (challenge, state_json) =
            self.webauthn
                .start_registration(username, display_name, &existing)?;

        let ceremony_token = generate_session_id()?;
        self.mfa_repo
            .create_challenge(&MfaChallenge {
                token: Arc::from(ceremony_token.as_str()),
                username: Arc::from(username),
                remember_me: false,
                kind: MfaMethod::Webauthn,
                state: Some(state_json),
                expires_at: expiry(self.challenge_ttl_secs),
            })
            .await?;

        info!(username = username, "Passkey registration started");
        Ok(RegistrationStart {
            challenge,
            ceremony_token,
        })
    }

    /// Complete registration and persist the credential.
    #[instrument(skip(self, response))]
    pub async fn finish(
        &self,
        username: &str,
        ceremony_token: &str,
        response: serde_json::Value,
        label: Option<String>,
    ) -> Result<(), DomainError> {
        let challenge = self
            .mfa_repo
            .get_challenge(ceremony_token)
            .await?
            .ok_or(DomainError::MfaChallengeExpired)?;

        if challenge.kind != MfaMethod::Webauthn
            || challenge.username.as_ref() != username
            || is_expired(&challenge.expires_at)
        {
            self.mfa_repo.delete_challenge(ceremony_token).await?;
            return Err(DomainError::MfaChallengeExpired);
        }

        let state = challenge
            .state
            .as_deref()
            .ok_or(DomainError::WebauthnError("missing ceremony state".into()))?;

        let registered = self.webauthn.finish_registration(response, state)?;

        self.mfa_repo
            .add_credential(&WebauthnCredential {
                id: None,
                username: Arc::from(username),
                credential_id: Arc::from(registered.credential_id.as_str()),
                label: label.map(|l| Arc::from(l.as_str())),
                passkey: registered.passkey_json,
                sign_count: registered.sign_count,
                created_at: None,
                last_used_at: None,
            })
            .await?;

        self.mfa_repo.delete_challenge(ceremony_token).await?;

        info!(username = username, "Passkey registered");
        Ok(())
    }
}

fn expiry(secs: i64) -> String {
    (chrono::Utc::now() + chrono::Duration::seconds(secs))
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

fn is_expired(expires_at: &str) -> bool {
    chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
        .map(|exp| chrono::Utc::now().naive_utc() > exp)
        .unwrap_or(true)
}
