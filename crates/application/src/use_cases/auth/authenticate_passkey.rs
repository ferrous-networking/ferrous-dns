use std::sync::Arc;

use tracing::{info, instrument};

use super::session_factory::build_session;
use crate::ports::{MfaRepository, SessionRepository, UserProvider, WebauthnService};
use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError, MfaChallenge, MfaMethod};

/// Authenticates a login challenge with a passkey (two-step: `start`/`finish`).
///
/// Reuses the same login challenge issued by `LoginUseCase` after the password
/// step, rewriting it to carry the WebAuthn ceremony state.
pub struct AuthenticatePasskeyUseCase {
    webauthn: Arc<dyn WebauthnService>,
    mfa_repo: Arc<dyn MfaRepository>,
    user_provider: Arc<dyn UserProvider>,
    session_repo: Arc<dyn SessionRepository>,
    auth_config: Arc<AuthConfig>,
}

impl AuthenticatePasskeyUseCase {
    pub fn new(
        webauthn: Arc<dyn WebauthnService>,
        mfa_repo: Arc<dyn MfaRepository>,
        user_provider: Arc<dyn UserProvider>,
        session_repo: Arc<dyn SessionRepository>,
        auth_config: Arc<AuthConfig>,
    ) -> Self {
        Self {
            webauthn,
            mfa_repo,
            user_provider,
            session_repo,
            auth_config,
        }
    }

    /// Begin authentication: returns the request challenge for
    /// `navigator.credentials.get`, keyed to the existing login challenge.
    #[instrument(skip(self))]
    pub async fn start(&self, challenge_token: &str) -> Result<serde_json::Value, DomainError> {
        if !self.webauthn.is_configured() {
            return Err(DomainError::WebauthnNotConfigured);
        }

        let challenge = self
            .mfa_repo
            .get_challenge(challenge_token)
            .await?
            .ok_or(DomainError::MfaChallengeExpired)?;

        if is_expired(&challenge.expires_at) {
            self.mfa_repo.delete_challenge(challenge_token).await?;
            return Err(DomainError::MfaChallengeExpired);
        }

        let username = challenge.username.clone();
        let passkeys: Vec<String> = self
            .mfa_repo
            .list_credentials(username.as_ref())
            .await?
            .into_iter()
            .map(|c| c.passkey)
            .collect();

        if passkeys.is_empty() {
            return Err(DomainError::MfaNotConfigured);
        }

        let (request, state_json) = self.webauthn.start_authentication(&passkeys)?;

        // Rewrite the challenge in place (same token/TTL) to carry the ceremony
        // state. No update method on the port, so delete-then-create.
        self.mfa_repo.delete_challenge(challenge_token).await?;
        self.mfa_repo
            .create_challenge(&MfaChallenge {
                token: Arc::from(challenge_token),
                username,
                remember_me: challenge.remember_me,
                kind: MfaMethod::Webauthn,
                state: Some(state_json),
                expires_at: challenge.expires_at,
            })
            .await?;

        Ok(request)
    }

    /// Complete authentication and mint the session.
    #[instrument(skip(self, response))]
    pub async fn finish(
        &self,
        challenge_token: &str,
        response: serde_json::Value,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<AuthSession, DomainError> {
        let challenge = self
            .mfa_repo
            .get_challenge(challenge_token)
            .await?
            .ok_or(DomainError::MfaChallengeExpired)?;

        if challenge.kind != MfaMethod::Webauthn || is_expired(&challenge.expires_at) {
            self.mfa_repo.delete_challenge(challenge_token).await?;
            return Err(DomainError::MfaChallengeExpired);
        }

        let state = challenge
            .state
            .as_deref()
            .ok_or(DomainError::WebauthnError("missing ceremony state".into()))?;

        let authenticated = self.webauthn.finish_authentication(response, state)?;

        self.mfa_repo
            .update_credential_counter(&authenticated.credential_id, authenticated.sign_count)
            .await?;

        let user = self
            .user_provider
            .get_by_username(challenge.username.as_ref())
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

        self.mfa_repo.delete_challenge(challenge_token).await?;

        let session = build_session(
            user.username.clone(),
            user.role.clone(),
            challenge.remember_me,
            ip_address,
            user_agent,
            &self.auth_config,
        )?;
        self.session_repo.create(&session).await?;

        info!(username = %user.username, "Passkey verified, user logged in");
        Ok(session)
    }
}

fn is_expired(expires_at: &str) -> bool {
    chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S")
        .map(|exp| chrono::Utc::now().naive_utc() > exp)
        .unwrap_or(true)
}
