use std::net::IpAddr;
use std::sync::Arc;

use tracing::{info, instrument, warn};

use super::login_rate_limiter::LoginRateLimiter;
use super::session_factory::{build_session, expires_in, random_hex_256, IssuedSession};
use crate::ports::{MfaRepository, PasswordHasher, SessionRepository, UserProvider};
use ferrous_dns_domain::{AuthConfig, DomainError, MfaChallenge, MfaMethod};

/// Result of a password check: either a full session, or a second factor is
/// required and a short-lived challenge has been issued.
pub enum LoginOutcome {
    /// Password was sufficient (no second factor enrolled) — session created.
    Authenticated(IssuedSession),
    /// Password was correct but a second factor is required.
    MfaRequired {
        /// Opaque challenge token the client echoes back to `/auth/2fa/verify`.
        challenge_token: String,
        /// Second-factor methods this account has enrolled.
        methods: Vec<MfaMethod>,
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
    rate_limiter: Arc<LoginRateLimiter>,
}

impl LoginUseCase {
    pub fn new(
        user_provider: Arc<dyn UserProvider>,
        session_repo: Arc<dyn SessionRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        mfa_repo: Arc<dyn MfaRepository>,
        auth_config: Arc<AuthConfig>,
    ) -> Self {
        let rate_limiter = Arc::new(LoginRateLimiter::from_config(&auth_config));
        Self {
            user_provider,
            session_repo,
            password_hasher,
            mfa_repo,
            auth_config,
            rate_limiter,
        }
    }

    /// Shares one lockout with the other credential checks, so failures on
    /// any of them count toward the same limit.
    pub fn with_rate_limiter(mut self, rate_limiter: Arc<LoginRateLimiter>) -> Self {
        self.rate_limiter = rate_limiter;
        self
    }

    /// Verify username + password, then branch on second-factor enrollment.
    ///
    /// Returns the created session (no factor enrolled) or an
    /// `MfaRequired` outcome carrying a challenge token. The caller is
    /// responsible for setting the `Set-Cookie` header on `Authenticated`.
    ///
    /// `peer_ip` is the TCP peer the lockout is keyed by; `ip_address` is only
    /// recorded on the session. A correct password that still needs a second
    /// factor does not clear earlier failures — otherwise knowing the password
    /// would buy unlimited second-factor guesses.
    #[instrument(skip(self, password))]
    pub async fn execute(
        &self,
        username: &str,
        password: &str,
        remember_me: bool,
        peer_ip: IpAddr,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<LoginOutcome, DomainError> {
        self.rate_limiter.check(peer_ip)?;

        let user = self.user_provider.get_by_username(username).await?;
        let Some(user) = user.filter(|user| user.enabled) else {
            self.rate_limiter.record_failure(peer_ip);
            return Err(DomainError::InvalidCredentials);
        };

        let valid = self
            .password_hasher
            .verify(password, &user.password_hash)
            .await?;

        if !valid {
            warn!(username = username, "Failed login attempt");
            self.rate_limiter.record_failure(peer_ip);
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
            let challenge_token = random_hex_256()?;
            let expires_at = expires_in(self.auth_config.mfa_challenge_ttl_secs)?;

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
                methods.push(MfaMethod::Totp);
            }
            if has_passkeys {
                methods.push(MfaMethod::Webauthn);
            }

            info!(username = username, "Password OK, second factor required");
            return Ok(LoginOutcome::MfaRequired {
                challenge_token,
                methods,
            });
        }

        let issued = build_session(
            user.username.clone(),
            user.role,
            remember_me,
            ip_address,
            user_agent,
            &self.auth_config,
        )?;

        self.session_repo.create(&issued.session).await?;
        self.rate_limiter.reset(peer_ip);

        info!(
            username = username,
            remember_me = remember_me,
            "User logged in"
        );
        Ok(LoginOutcome::Authenticated(issued))
    }

    /// Returns the `max_age` in seconds for the session cookie.
    pub fn session_max_age(&self, remember_me: bool) -> i64 {
        self.auth_config.session_ttl_secs(remember_me)
    }
}
