use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::{info, instrument};

use ferrous_dns_application::ports::{ApiKeyMaterial, ApiTokenRepository};
use ferrous_dns_domain::{ApiToken, DomainError};

use crate::repositories::{db_err, is_unique_violation, sql_now};

pub struct SqliteApiTokenRepository {
    pool: SqlitePool,
}

impl SqliteApiTokenRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[derive(sqlx::FromRow)]
struct TokenRow {
    id: i64,
    name: String,
    key_prefix: String,
    key_hash: String,
    created_at: String,
    last_used_at: Option<String>,
}

#[async_trait]
impl ApiTokenRepository for SqliteApiTokenRepository {
    #[instrument(skip(self, key_hash))]
    async fn create(
        &self,
        name: &str,
        key_prefix: &str,
        key_hash: &str,
    ) -> Result<ApiToken, DomainError> {
        let now = sql_now();

        let row: TokenRow = sqlx::query_as(
            "INSERT INTO api_tokens (name, key_prefix, key_hash, created_at)
             VALUES (?, ?, ?, ?)
             RETURNING id, name, key_prefix, key_hash, created_at, last_used_at",
        )
        .bind(name)
        .bind(key_prefix)
        .bind(key_hash)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::DuplicateApiTokenName(name.to_string())
            } else {
                db_err("Failed to create API token")(e)
            }
        })?;

        info!(name = name, "API token created");
        Ok(row_to_token(row))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<ApiToken>, DomainError> {
        let rows: Vec<TokenRow> = sqlx::query_as(
            "SELECT id, name, key_prefix, key_hash, created_at, last_used_at
             FROM api_tokens ORDER BY id",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to get all API tokens"))?;

        Ok(rows.into_iter().map(row_to_token).collect())
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<ApiToken>, DomainError> {
        let row: Option<TokenRow> = sqlx::query_as(
            "SELECT id, name, key_prefix, key_hash, created_at, last_used_at
             FROM api_tokens WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to get API token by id"))?;

        Ok(row.map(row_to_token))
    }

    #[instrument(skip(self))]
    async fn get_by_name(&self, name: &str) -> Result<Option<ApiToken>, DomainError> {
        let row: Option<TokenRow> = sqlx::query_as(
            "SELECT id, name, key_prefix, key_hash, created_at, last_used_at
             FROM api_tokens WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to get API token by name"))?;

        Ok(row.map(row_to_token))
    }

    #[instrument(skip(self, new_key))]
    async fn update(
        &self,
        id: i64,
        name: &str,
        new_key: Option<ApiKeyMaterial<'_>>,
    ) -> Result<ApiToken, DomainError> {
        let row: Option<TokenRow> = match new_key {
            Some(key) => {
                sqlx::query_as(
                    "UPDATE api_tokens SET name = ?, key_prefix = ?, key_hash = ?
                 WHERE id = ?
                 RETURNING id, name, key_prefix, key_hash, created_at, last_used_at",
                )
                .bind(name)
                .bind(key.prefix)
                .bind(key.hash)
                .bind(id)
                .fetch_optional(&self.pool)
                .await
            }
            None => {
                sqlx::query_as(
                    "UPDATE api_tokens SET name = ?
                 WHERE id = ?
                 RETURNING id, name, key_prefix, key_hash, created_at, last_used_at",
                )
                .bind(name)
                .bind(id)
                .fetch_optional(&self.pool)
                .await
            }
        }
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::DuplicateApiTokenName(name.to_string())
            } else {
                db_err("Failed to update API token")(e)
            }
        })?;

        row.map(row_to_token)
            .ok_or(DomainError::ApiTokenNotFound(id))
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM api_tokens WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete API token"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::ApiTokenNotFound(id));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_last_used(&self, id: i64) -> Result<(), DomainError> {
        sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
            .bind(sql_now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to update API token last_used"))?;

        Ok(())
    }

    #[instrument(skip(self, key_hash))]
    async fn get_id_by_hash(&self, key_hash: &str) -> Result<Option<i64>, DomainError> {
        let row: Option<(i64,)> = sqlx::query_as("SELECT id FROM api_tokens WHERE key_hash = ?")
            .bind(key_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err("Failed to get API token by hash"))?;

        Ok(row.map(|(id,)| id))
    }
}

fn row_to_token(row: TokenRow) -> ApiToken {
    ApiToken {
        id: Some(row.id),
        name: Arc::from(row.name.as_str()),
        key_prefix: Arc::from(row.key_prefix.as_str()),
        key_hash: Arc::from(row.key_hash.as_str()),
        created_at: Some(row.created_at),
        last_used_at: row.last_used_at,
    }
}
