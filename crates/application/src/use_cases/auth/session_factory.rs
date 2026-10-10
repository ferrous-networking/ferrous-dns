use std::fmt::Write;
use std::sync::Arc;

use ring::rand::SecureRandom;

use ferrous_dns_domain::config::auth::expiry_from_now;
use ferrous_dns_domain::{AuthConfig, AuthSession, DomainError, UserRole};

/// UTC storage format of every auth timestamp; lexicographic order matches time order.
pub(crate) const TIMESTAMP_FMT: &str = "%Y-%m-%d %H:%M:%S";

/// 256-bit CSPRNG value, hex-encoded; used for session ids, ceremony tokens and API keys.
pub(crate) fn random_hex_256() -> Result<String, DomainError> {
    let mut buf = [0u8; 32];
    ring::rand::SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| DomainError::IoError("CSPRNG fill failed".to_string()))?;
    Ok(hex_encode(&buf))
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Timestamp `ttl_secs` from now, in [`TIMESTAMP_FMT`]. Config validation
/// rejects TTLs whose expiry cannot be stored; this refuses the login instead
/// of panicking or writing a five-digit year.
pub(crate) fn expires_in(ttl_secs: i64) -> Result<String, DomainError> {
    expiry_from_now(ttl_secs)
        .map(|at| at.format(TIMESTAMP_FMT).to_string())
        .ok_or_else(|| {
            DomainError::ConfigError(format!("an expiry {ttl_secs}s from now is out of range"))
        })
}

/// Whether a [`TIMESTAMP_FMT`] timestamp has passed; unparseable values count as expired.
pub(crate) fn is_expired(expires_at: &str) -> bool {
    chrono::NaiveDateTime::parse_from_str(expires_at, TIMESTAMP_FMT)
        .map(|exp| chrono::Utc::now().naive_utc() > exp)
        .unwrap_or(true)
}

/// Whether a [`TIMESTAMP_FMT`] timestamp is at least `secs` old; unparseable values count as old.
pub(crate) fn is_older_than(at: &str, secs: i64) -> bool {
    chrono::NaiveDateTime::parse_from_str(at, TIMESTAMP_FMT)
        .map(|at| chrono::Utc::now().naive_utc() - at >= chrono::TimeDelta::seconds(secs))
        .unwrap_or(true)
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
    let session_id = random_hex_256()?;
    let created_at = chrono::Utc::now().format(TIMESTAMP_FMT).to_string();
    let expires_at = expires_in(config.session_ttl_secs(remember_me))?;

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
