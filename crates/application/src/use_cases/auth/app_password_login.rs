use std::net::IpAddr;
use std::sync::Arc;

use tracing::{info, instrument};

use super::login_rate_limiter::LoginRateLimiter;
use super::session_factory::{build_session, IssuedSession};
use crate::ports::{SessionRepository, UserProvider};
use crate::use_cases::api_tokens::ValidateApiTokenUseCase;
use ferrous_dns_domain::{AuthConfig, DomainError};

/// Logs a user in with an API token in place of the password — Pi-hole v6's
/// "app password". Like Pi-hole's, it skips the second factor: the token is a
/// 256-bit random secret the admin minted on purpose, not a memorised password.
///
/// A wrong token does not count toward the lockout. Its one caller goes on to
/// try the same text as the account password, and that check counts the
/// failure; counting it here too would halve the configured attempts.
pub struct AppPasswordLoginUseCase {
    validate_api_token: Arc<ValidateApiTokenUseCase>,
    user_provider: Arc<dyn UserProvider>,
    session_repo: Arc<dyn SessionRepository>,
    auth_config: Arc<AuthConfig>,
    rate_limiter: Arc<LoginRateLimiter>,
}

impl AppPasswordLoginUseCase {
    pub fn new(
        validate_api_token: Arc<ValidateApiTokenUseCase>,
        user_provider: Arc<dyn UserProvider>,
        session_repo: Arc<dyn SessionRepository>,
        auth_config: Arc<AuthConfig>,
        rate_limiter: Arc<LoginRateLimiter>,
    ) -> Self {
        Self {
            validate_api_token,
            user_provider,
            session_repo,
            auth_config,
            rate_limiter,
        }
    }

    /// Creates a session for `username` when `token` is a valid API token.
    #[instrument(skip(self, token))]
    pub async fn execute(
        &self,
        username: &str,
        token: &str,
        peer_ip: IpAddr,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<IssuedSession, DomainError> {
        self.rate_limiter.check(peer_ip)?;
        self.validate_api_token.execute(token).await?;

        let user = self
            .user_provider
            .get_by_username(username)
            .await?
            .filter(|user| user.enabled)
            .ok_or(DomainError::InvalidCredentials)?;

        let issued = build_session(
            user.username.clone(),
            user.role,
            false,
            ip_address,
            user_agent,
            &self.auth_config,
        )?;
        self.session_repo.create(&issued.session).await?;
        self.rate_limiter.reset(peer_ip);

        info!(username = username, "User logged in with an app password");
        Ok(issued)
    }
}
