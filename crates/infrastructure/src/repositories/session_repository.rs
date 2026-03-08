use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::{error, instrument};

use ferrous_dns_application::ports::SessionRepository;
use ferrous_dns_domain::{AuthSession, DomainError, UserRole};

pub struct SqliteSessionRepository {
    pool: Arc<SqlitePool>,
}

impl SqliteSessionRepository {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for SqliteSessionRepository {
    #[instrument(skip(self, session))]
    async fn create(&self, session: &AuthSession) -> Result<(), DomainError> {
        let remember = if session.remember_me { 1i32 } else { 0 };

        sqlx::query(
            "INSERT INTO auth_sessions (id, username, role, ip_address, user_agent, remember_me, created_at, last_seen_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session.id.as_ref())
        .bind(session.username.as_ref())
        .bind(session.role.as_str())
        .bind(session.ip_address.as_ref())
        .bind(session.user_agent.as_ref())
        .bind(remember)
        .bind(&session.created_at)
        .bind(&session.last_seen_at)
        .bind(&session.expires_at)
        .execute(self.pool.as_ref())
        .await
        .map_err(|e| {
            error!("Failed to create session: {e}");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: &str) -> Result<Option<AuthSession>, DomainError> {
        let row: Option<(String, String, String, String, String, i32, String, String, String)> =
            sqlx::query_as(
                "SELECT id, username, role, ip_address, user_agent, remember_me, created_at, last_seen_at, expires_at
                 FROM auth_sessions WHERE id = ?",
            )
            .bind(id)
            .fetch_optional(self.pool.as_ref())
            .await
            .map_err(|e| {
                error!("Failed to get session: {e}");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(row.map(row_to_session))
    }

    #[instrument(skip(self))]
    async fn update_last_seen(&self, id: &str) -> Result<(), DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        sqlx::query("UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| {
                error!("Failed to update session last_seen: {e}");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: &str) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM auth_sessions WHERE id = ?")
            .bind(id)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| {
                error!("Failed to delete session: {e}");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_expired(&self) -> Result<u64, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let result = sqlx::query("DELETE FROM auth_sessions WHERE expires_at < ?")
            .bind(&now)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| {
                error!("Failed to delete expired sessions: {e}");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(result.rows_affected())
    }

    #[instrument(skip(self))]
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let rows: Vec<(String, String, String, String, String, i32, String, String, String)> =
            sqlx::query_as(
                "SELECT id, username, role, ip_address, user_agent, remember_me, created_at, last_seen_at, expires_at
                 FROM auth_sessions WHERE expires_at >= ? ORDER BY last_seen_at DESC",
            )
            .bind(&now)
            .fetch_all(self.pool.as_ref())
            .await
            .map_err(|e| {
                error!("Failed to get active sessions: {e}");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(rows.into_iter().map(row_to_session).collect())
    }
}

fn row_to_session(
    row: (
        String,
        String,
        String,
        String,
        String,
        i32,
        String,
        String,
        String,
    ),
) -> AuthSession {
    let role = UserRole::parse(&row.2).unwrap_or_else(|_| {
        tracing::error!(
            role = row.2,
            "Invalid session role in database, defaulting to Viewer"
        );
        UserRole::Viewer
    });
    AuthSession {
        id: Arc::from(row.0.as_str()),
        username: Arc::from(row.1.as_str()),
        role,
        ip_address: Arc::from(row.3.as_str()),
        user_agent: Arc::from(row.4.as_str()),
        remember_me: row.5 != 0,
        created_at: row.6,
        last_seen_at: row.7,
        expires_at: row.8,
    }
}
