use std::sync::Arc;

use tracing::{info, instrument, warn};

use super::session_factory::{build_session, generate_session_id, session_max_age};
use crate::ports::{MfaRepository, PasswordHasher, SessionRepository, UserProvider};
use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError, MfaChallenge, MfaMethod};

/// Result of a password check: either a full session, or a second factor is
/// required and a short-lived challenge has been issued.
pub enum LoginOutcome {
    /// Password was sufficient (no second factor enrolled) — session created.
    Authenticated(AuthSession),
    /// Password was correct but a second factor is required.
    MfaRequired {
        /// Opaque challenge token the client echoes back to `/auth/2fa/verify`.
        challenge_token: String,
        /// Which second-factor methods this account has enrolled
        /// (`"totp"` and/or `"webauthn"`).
        methods: Vec<&'static str>,
    },
}

/// Authenticates a user and either creates a browser session or issues an MFA
/// challenge when a second factor is enrolled.
pub struct LoginUseCase {
    user_provider: Arc<dyn UserProvider>,
    session_repo: Arc<dyn SessionRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    mfa_repo: Arc<dyn MfaRepository>,
    auth_config: Arc<AuthConfig>,
}

impl LoginUseCase {
    pub fn new(
        user_provider: Arc<dyn UserProvider>,
        session_repo: Arc<dyn SessionRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        mfa_repo: Arc<dyn MfaRepository>,
        auth_config: Arc<AuthConfig>,
    ) -> Self {
        Self {
            user_provider,
            session_repo,
            password_hasher,
            mfa_repo,
            auth_config,
        }
    }

    /// Verify username + password, then branch on second-factor enrollment.
    ///
    /// Returns the created `AuthSession` (no factor enrolled) or an
    /// `MfaRequired` outcome carrying a challenge token. The caller is
    /// responsible for setting the `Set-Cookie` header on `Authenticated`.
    #[instrument(skip(self, password))]
    pub async fn execute(
        &self,
        username: &str,
        password: &str,
        remember_me: bool,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<LoginOutcome, DomainError> {
        let user = self
            .user_provider
            .get_by_username(username)
            .await?
            .ok_or(DomainError::InvalidCredentials)?;

        if !user.enabled {
            return Err(DomainError::InvalidCredentials);
        }

        let valid = self.password_hasher.verify(password, &user.password_hash)?;

        if !valid {
            warn!(username = username, "Failed login attempt");
            return Err(DomainError::InvalidCredentials);
        }

        // Determine which (if any) second factors are enrolled.
        let totp_enabled = self
            .mfa_repo
            .get(username)
            .await?
            .map(|m| m.totp_enabled)
            .unwrap_or(false);
        let has_passkeys = self.mfa_repo.has_credentials(username).await?;

        if totp_enabled || has_passkeys {
            let challenge_token = generate_session_id()?;
            let expires_at = (chrono::Utc::now()
                + chrono::Duration::seconds(self.auth_config.mfa_challenge_ttl_secs))
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

            self.mfa_repo
                .create_challenge(&MfaChallenge {
                    token: Arc::from(challenge_token.as_str()),
                    username: user.username.clone(),
                    remember_me,
                    // TOTP is the default carrier; WebAuthn ceremonies write
                    // their own challenge on `/auth/webauthn/authenticate/start`.
                    kind: MfaMethod::Totp,
                    state: None,
                    expires_at,
                })
                .await?;

            let mut methods = Vec::new();
            if totp_enabled {
                methods.push("totp");
            }
            if has_passkeys {
                methods.push("webauthn");
            }

            info!(username = username, "Password OK, second factor required");
            return Ok(LoginOutcome::MfaRequired {
                challenge_token,
                methods,
            });
        }

        let session = build_session(
            user.username.clone(),
            user.role.clone(),
            remember_me,
            ip_address,
            user_agent,
            &self.auth_config,
        )?;

        self.session_repo.create(&session).await?;

        info!(
            username = username,
            remember_me = remember_me,
            "User logged in"
        );
        Ok(LoginOutcome::Authenticated(session))
    }

    /// Returns the `max_age` in seconds for the session cookie.
    pub fn session_max_age(&self, remember_me: bool) -> i64 {
        session_max_age(remember_me, &self.auth_config)
    }
}
