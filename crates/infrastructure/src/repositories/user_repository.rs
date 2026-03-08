use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::{error, info, instrument};

use ferrous_dns_application::ports::UserRepository;
use ferrous_dns_domain::{DomainError, User, UserRole, UserSource};

pub struct SqliteUserRepository {
    pool: Arc<SqlitePool>,
}

impl SqliteUserRepository {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }
}

type UserRow = (
    i64,
    String,
    Option<String>,
    String,
    String,
    bool,
    String,
    String,
);

#[async_trait]
impl UserRepository for SqliteUserRepository {
    #[instrument(skip(self, password_hash))]
    async fn create(
        &self,
        username: &str,
        display_name: Option<&str>,
        password_hash: &str,
        role: &str,
    ) -> Result<User, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let row: UserRow = sqlx::query_as(
            "INSERT INTO users (username, display_name, password_hash, role, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, 1, ?, ?)
             RETURNING id, username, display_name, password_hash, role, enabled, created_at, updated_at",
        )
        .bind(username)
        .bind(display_name)
        .bind(password_hash)
        .bind(role)
        .bind(&now)
        .bind(&now)
        .fetch_one(self.pool.as_ref())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
                DomainError::DuplicateUsername(username.to_string())
            }
            _ => {
                error!("Failed to create user: {e}");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        info!(username = username, "User created in database");
        Ok(row_to_user(row))
    }

    #[instrument(skip(self))]
    async fn get_by_username(&self, username: &str) -> Result<Option<User>, DomainError> {
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, username, display_name, password_hash, role, enabled, created_at, updated_at
             FROM users WHERE username = ?",
        )
        .bind(username)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(|e| {
            error!("Failed to get user by username: {e}");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(row_to_user))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<User>, DomainError> {
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, username, display_name, password_hash, role, enabled, created_at, updated_at
             FROM users WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(|e| {
            error!("Failed to get user by id: {e}");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(row_to_user))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<User>, DomainError> {
        let rows: Vec<UserRow> = sqlx::query_as(
            "SELECT id, username, display_name, password_hash, role, enabled, created_at, updated_at
             FROM users ORDER BY id",
        )
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(|e| {
            error!("Failed to get all users: {e}");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(row_to_user).collect())
    }

    #[instrument(skip(self, password_hash))]
    async fn update_password(&self, id: i64, password_hash: &str) -> Result<(), DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        sqlx::query("UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?")
            .bind(password_hash)
            .bind(&now)
            .bind(id)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| {
                error!("Failed to update user password: {e}");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM users WHERE id = ?")
            .bind(id)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| {
                error!("Failed to delete user: {e}");
                DomainError::DatabaseError(e.to_string())
            })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::UserNotFound(id.to_string()));
        }

        Ok(())
    }
}

fn row_to_user(row: UserRow) -> User {
    let role = UserRole::parse(&row.4).unwrap_or_else(|_| {
        tracing::error!(
            role = row.4,
            "Invalid user role in database, defaulting to Viewer"
        );
        UserRole::Viewer
    });
    User {
        id: Some(row.0),
        username: Arc::from(row.1.as_str()),
        display_name: row.2.map(|s| Arc::from(s.as_str())),
        password_hash: Arc::from(row.3.as_str()),
        role,
        source: UserSource::Database,
        enabled: row.5,
        created_at: Some(row.6),
        updated_at: Some(row.7),
    }
}
