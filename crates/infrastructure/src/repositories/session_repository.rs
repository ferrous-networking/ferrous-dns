use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::{error, instrument};

use ferrous_dns_application::ports::SessionRepository;
use ferrous_dns_domain::{AuthSession, DomainError, UserRole};

use crate::repositories::{db_err, sql_now};

pub struct SqliteSessionRepository {
    pool: SqlitePool,
    /// Session lookups run on every authenticated request; reading them off the write
    /// pool keeps the UI answering while writers queue for the write lock.
    read_pool: SqlitePool,
}

impl SqliteSessionRepository {
    pub fn new(pool: SqlitePool, read_pool: SqlitePool) -> Self {
        Self { pool, read_pool }
    }
}

type SessionRow = (
    String,
    String,
    String,
    String,
    String,
    bool,
    String,
    String,
    String,
);

#[async_trait]
impl SessionRepository for SqliteSessionRepository {
    #[instrument(skip(self, session))]
    async fn create(&self, session: &AuthSession) -> Result<(), DomainError> {
        sqlx::query(
            "INSERT INTO auth_sessions (id, username, role, ip_address, user_agent, remember_me, created_at, last_seen_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(session.id.as_ref())
        .bind(session.username.as_ref())
        .bind(session.role.as_str())
        .bind(session.ip_address.as_ref())
        .bind(session.user_agent.as_ref())
        .bind(session.remember_me)
        .bind(&session.created_at)
        .bind(&session.last_seen_at)
        .bind(&session.expires_at)
        .execute(&self.pool)
        .await
        .map_err(db_err("Failed to create session"))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: &str) -> Result<Option<AuthSession>, DomainError> {
        let row: Option<SessionRow> = sqlx::query_as(
            "SELECT id, username, role, ip_address, user_agent, remember_me, created_at, last_seen_at, expires_at
             FROM auth_sessions WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.read_pool)
        .await
        .map_err(db_err("Failed to get session"))?;

        Ok(row.map(row_to_session))
    }

    #[instrument(skip(self))]
    async fn update_last_seen(&self, id: &str) -> Result<(), DomainError> {
        sqlx::query("UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?")
            .bind(sql_now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to update session last_seen"))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: &str) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM auth_sessions WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete session"))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete_expired(&self) -> Result<u64, DomainError> {
        let result = sqlx::query("DELETE FROM auth_sessions WHERE expires_at < ?")
            .bind(sql_now())
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete expired sessions"))?;

        Ok(result.rows_affected())
    }

    #[instrument(skip(self, keep_id))]
    async fn delete_other_sessions(
        &self,
        username: &str,
        keep_id: &str,
    ) -> Result<u64, DomainError> {
        let result = sqlx::query("DELETE FROM auth_sessions WHERE username = ? AND id <> ?")
            .bind(username)
            .bind(keep_id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete other sessions"))?;

        Ok(result.rows_affected())
    }

    #[instrument(skip(self))]
    async fn get_all_active(&self) -> Result<Vec<AuthSession>, DomainError> {
        let rows: Vec<SessionRow> = sqlx::query_as(
            "SELECT id, username, role, ip_address, user_agent, remember_me, created_at, last_seen_at, expires_at
             FROM auth_sessions WHERE expires_at >= ? ORDER BY last_seen_at DESC",
        )
        .bind(sql_now())
        .fetch_all(&self.read_pool)
        .await
        .map_err(db_err("Failed to get active sessions"))?;

        Ok(rows.into_iter().map(row_to_session).collect())
    }
}

fn row_to_session(
    (
        id,
        username,
        role,
        ip_address,
        user_agent,
        remember_me,
        created_at,
        last_seen_at,
        expires_at,
    ): SessionRow,
) -> AuthSession {
    let role = role.parse::<UserRole>().unwrap_or_else(|e| {
        error!(error = %e, "Invalid session role in database, defaulting to Viewer");
        UserRole::Viewer
    });
    AuthSession {
        id: Arc::from(id.as_str()),
        username: Arc::from(username.as_str()),
        role,
        ip_address: Arc::from(ip_address.as_str()),
        user_agent: Arc::from(user_agent.as_str()),
        remember_me,
        created_at,
        last_seen_at,
        expires_at,
    }
}
