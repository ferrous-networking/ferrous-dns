use super::user::UserRole;
use std::sync::Arc;

/// An authenticated browser session, stored in SQLite.
///
/// Sessions use `HttpOnly; SameSite=Strict` cookies. TTL depends on whether
/// the user checked "Remember Me" at login:
/// - Without: `session_ttl_hours` (default 24h)
/// - With: `remember_me_days` (default 30 days)
///
/// There is no concurrent session limit.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub id: Arc<str>,
    pub username: Arc<str>,
    pub role: UserRole,
    pub ip_address: Arc<str>,
    pub user_agent: Arc<str>,
    pub remember_me: bool,
    pub created_at: String,
    pub last_seen_at: String,
    pub expires_at: String,
}
