use std::sync::Arc;

use tracing::{info, instrument};

use super::session_factory::{build_session, generate_session_id};
use crate::ports::{MfaRepository, SessionRepository, UserProvider, WebauthnService};
use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError, MfaChallenge, MfaMethod};

/// Usernameless ("discoverable") passkey login: authenticates with a resident
/// credential alone — no username, no password. The passkey (which requires
/// user verification) is accepted as sufficient, so this mints a full session.
///
/// Two-step ceremony: `start` issues an anonymous challenge; `finish` resolves
/// the owning user from the assertion's credential id.
pub struct DiscoverablePasskeyLoginUseCase {
    webauthn: Arc<dyn WebauthnService>,
    mfa_repo: Arc<dyn MfaRepository>,
    user_provider: Arc<dyn UserProvider>,
    session_repo: Arc<dyn SessionRepository>,
    auth_config: Arc<AuthConfig>,
    /// TTL of the anonymous discoverable challenge, in seconds.
    challenge_ttl_secs: i64,
}

/// The browser-facing request challenge plus the ceremony token to echo back.
pub struct DiscoverableStart {
    pub challenge: serde_json::Value,
    pub challenge_token: String,
}

impl DiscoverablePasskeyLoginUseCase {
    pub fn new(
        webauthn: Arc<dyn WebauthnService>,
        mfa_repo: Arc<dyn MfaRepository>,
        user_provider: Arc<dyn UserProvider>,
        session_repo: Arc<dyn SessionRepository>,
        auth_config: Arc<AuthConfig>,
        challenge_ttl_secs: i64,
    ) -> Self {
        Self {
            webauthn,
            mfa_repo,
            user_provider,
            session_repo,
            auth_config,
            challenge_ttl_secs,
        }
    }

    /// Begin: returns the request challenge for `navigator.credentials.get`
    /// (empty `allowCredentials`) and a ceremony token.
    #[instrument(skip(self))]
    pub async fn start(&self) -> Result<DiscoverableStart, DomainError> {
        let (challenge, state_json) = self.webauthn.start_discoverable()?;

        let challenge_token = generate_session_id()?;
        self.mfa_repo
            .create_challenge(&MfaChallenge {
                token: Arc::from(challenge_token.as_str()),
                // Anonymous — the user is unknown until `finish` identifies them.
                username: Arc::from(""),
                remember_me: false,
                kind: MfaMethod::Webauthn,
                state: Some(state_json),
                expires_at: expiry(self.challenge_ttl_secs),
            })
            .await?;

        Ok(DiscoverableStart {
            challenge,
            challenge_token,
        })
    }

    /// Complete: resolve the user from the assertion, verify it, mint a session.
    #[instrument(skip(self, response))]
    pub async fn finish(
        &self,
        challenge_token: &str,
        response: serde_json::Value,
        remember_me: bool,
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

        // Resolve which stored credential (and user) signed the assertion.
        let credential_id = self.webauthn.identify_discoverable(response.clone())?;
        let credential = self
            .mfa_repo
            .find_credential_by_id(&credential_id)
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

        let authenticated =
            self.webauthn
                .finish_discoverable(response, state, &credential.passkey)?;

        self.mfa_repo
            .update_credential_counter(&authenticated.credential_id, authenticated.sign_count)
            .await?;

        let user = self
            .user_provider
            .get_by_username(credential.username.as_ref())
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

        // Discoverable login is the entry point (no upstream LoginUseCase), so the
        // disabled-account gate must be enforced here.
        if !user.enabled {
            return Err(DomainError::InvalidCredentials);
        }

        self.mfa_repo.delete_challenge(challenge_token).await?;

        let session = build_session(
            user.username.clone(),
            user.role.clone(),
            remember_me,
            ip_address,
            user_agent,
            &self.auth_config,
        )?;
        self.session_repo.create(&session).await?;

        info!(username = %user.username, "Passwordless passkey login");
        Ok(session)
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
