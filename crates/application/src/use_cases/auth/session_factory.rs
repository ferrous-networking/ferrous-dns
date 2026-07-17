use std::fmt::Write;
use std::sync::Arc;

use ring::rand::SecureRandom;

use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError, UserRole};

/// Generates a 256-bit CSPRNG session id, hex-encoded.
pub(crate) fn generate_session_id() -> Result<String, DomainError> {
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

/// Builds a fresh `AuthSession` for an authenticated user.
///
/// Shared by the password-only login path and the second-factor verify path so
/// session shape (id, TTL, timestamps) stays identical.
pub(crate) fn build_session(
    username: Arc<str>,
    role: UserRole,
    remember_me: bool,
    ip_address: &str,
    user_agent: &str,
    config: &AuthConfig,
) -> Result<AuthSession, DomainError> {
    let session_id = generate_session_id()?;
    let now = chrono::Utc::now();
    let created_at = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let expires_at = compute_expiry(remember_me, config);

    Ok(AuthSession {
        id: Arc::from(session_id.as_str()),
        username,
        role,
        ip_address: Arc::from(ip_address),
        user_agent: Arc::from(user_agent),
        remember_me,
        last_seen_at: created_at.clone(),
        created_at,
        expires_at,
    })
}

/// Cookie `max_age` in seconds for the session.
pub(crate) fn session_max_age(remember_me: bool, config: &AuthConfig) -> i64 {
    if remember_me {
        i64::from(config.remember_me_days) * 86400
    } else {
        i64::from(config.session_ttl_hours) * 3600
    }
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
