use std::fmt::Write;
use std::sync::Arc;

use ring::rand::SecureRandom;
use tracing::{info, instrument, warn};

use crate::ports::{PasswordHasher, SessionRepository, UserProvider};
use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError};

/// Authenticates a user and creates a browser session.
pub struct LoginUseCase {
    user_provider: Arc<dyn UserProvider>,
    session_repo: Arc<dyn SessionRepository>,
    password_hasher: Arc<dyn PasswordHasher>,
    auth_config: Arc<AuthConfig>,
}

impl LoginUseCase {
    pub fn new(
        user_provider: Arc<dyn UserProvider>,
        session_repo: Arc<dyn SessionRepository>,
        password_hasher: Arc<dyn PasswordHasher>,
        auth_config: Arc<AuthConfig>,
    ) -> Self {
        Self {
            user_provider,
            session_repo,
            password_hasher,
            auth_config,
        }
    }

    /// Authenticate with username + password and create a session.
    ///
    /// Returns the created `AuthSession` with a CSPRNG session ID.
    /// The caller is responsible for setting the `Set-Cookie` header.
    #[instrument(skip(self, password))]
    pub async fn execute(
        &self,
        username: &str,
        password: &str,
        remember_me: bool,
        ip_address: &str,
        user_agent: &str,
    ) -> Result<AuthSession, DomainError> {
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

        let session_id = generate_session_id()?;
        let now = chrono::Utc::now();
        let created_at = now.format("%Y-%m-%d %H:%M:%S").to_string();
        let expires_at = compute_expiry(remember_me, &self.auth_config);

        let session = AuthSession {
            id: Arc::from(session_id.as_str()),
            username: user.username.clone(),
            role: user.role.clone(),
            ip_address: Arc::from(ip_address),
            user_agent: Arc::from(user_agent),
            remember_me,
            last_seen_at: created_at.clone(),
            created_at,
            expires_at,
        };

        self.session_repo.create(&session).await?;

        info!(
            username = username,
            remember_me = remember_me,
            "User logged in"
        );
        Ok(session)
    }

    /// Returns the `max_age` in seconds for the session cookie.
    pub fn session_max_age(&self, remember_me: bool) -> i64 {
        if remember_me {
            i64::from(self.auth_config.remember_me_days) * 86400
        } else {
            i64::from(self.auth_config.session_ttl_hours) * 3600
        }
    }
}

fn generate_session_id() -> Result<String, DomainError> {
    let mut buf = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| DomainError::IoError("CSPRNG fill failed".to_string()))?;
    let mut hex = String::with_capacity(64);
    for byte in &buf {
        let _ = write!(hex, "{byte:02x}");
    }
    Ok(hex)
}

fn compute_expiry(remember_me: bool, config: &AuthConfig) -> String {
    let duration = if remember_me {
        chrono::Duration::days(i64::from(config.remember_me_days))
    } else {
        chrono::Duration::hours(i64::from(config.session_ttl_hours))
    };
    let expires = chrono::Utc::now() + duration;
    expires.format("%Y-%m-%d %H:%M:%S").to_string()
}
