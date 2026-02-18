use async_trait::async_trait;
use ferrous_dns_application::ports::WhitelistSourceRepository;
use ferrous_dns_domain::{DomainError, WhitelistSource};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{error, instrument};

type WhitelistSourceRow = (
    i64,
    String,
    Option<String>,
    i64,
    Option<String>,
    i64,
    String,
    String,
);

pub struct SqliteWhitelistSourceRepository {
    pool: SqlitePool,
}

impl SqliteWhitelistSourceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_source(row: WhitelistSourceRow) -> WhitelistSource {
        let (id, name, url, group_id, comment, enabled, created_at, updated_at) = row;
        WhitelistSource {
            id: Some(id),
            name: Arc::from(name.as_str()),
            url: url.map(|s| Arc::from(s.as_str())),
            group_id,
            comment: comment.map(|s| Arc::from(s.as_str())),
            enabled: enabled != 0,
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }
}

#[async_trait]
impl WhitelistSourceRepository for SqliteWhitelistSourceRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: String,
        url: Option<String>,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<WhitelistSource, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let result = sqlx::query(
            "INSERT INTO whitelist_sources (name, url, group_id, comment, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&name)
        .bind(&url)
        .bind(group_id)
        .bind(&comment)
        .bind(if enabled { 1i64 } else { 0i64 })
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::InvalidWhitelistSource(format!(
                    "Whitelist source '{}' already exists",
                    name
                ))
            } else {
                error!(error = %e, "Failed to create whitelist source");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        let id = result.last_insert_rowid();

        self.get_by_id(id).await?.ok_or_else(|| {
            DomainError::DatabaseError("Failed to fetch created whitelist source".to_string())
        })
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<WhitelistSource>, DomainError> {
        let row = sqlx::query_as::<_, WhitelistSourceRow>(
            "SELECT id, name, url, group_id, comment, enabled, created_at, updated_at
             FROM whitelist_sources WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query whitelist source by id");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Self::row_to_source))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<WhitelistSource>, DomainError> {
        let rows = sqlx::query_as::<_, WhitelistSourceRow>(
            "SELECT id, name, url, group_id, comment, enabled, created_at, updated_at
             FROM whitelist_sources ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query all whitelist sources");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Self::row_to_source).collect())
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        url: Option<Option<String>>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<WhitelistSource, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let current = self.get_by_id(id).await?.ok_or_else(|| {
            DomainError::WhitelistSourceNotFound(format!("Whitelist source {} not found", id))
        })?;

        let final_name = name.unwrap_or_else(|| current.name.to_string());
        let final_url: Option<String> = match url {
            Some(u) => u,
            None => current.url.as_ref().map(|s| s.to_string()),
        };
        let final_group_id = group_id.unwrap_or(current.group_id);
        let final_comment: Option<String> =
            comment.or_else(|| current.comment.as_ref().map(|s| s.to_string()));
        let final_enabled = enabled.unwrap_or(current.enabled);

        let result = sqlx::query(
            "UPDATE whitelist_sources
             SET name = ?, url = ?, group_id = ?, comment = ?, enabled = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(&final_name)
        .bind(&final_url)
        .bind(final_group_id)
        .bind(&final_comment)
        .bind(if final_enabled { 1i64 } else { 0i64 })
        .bind(&now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::InvalidWhitelistSource(format!(
                    "Whitelist source '{}' already exists",
                    final_name
                ))
            } else {
                error!(error = %e, "Failed to update whitelist source");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::WhitelistSourceNotFound(format!(
                "Whitelist source {} not found",
                id
            )));
        }

        self.get_by_id(id).await?.ok_or_else(|| {
            DomainError::DatabaseError("Failed to fetch updated whitelist source".to_string())
        })
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM whitelist_sources WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete whitelist source");
                DomainError::DatabaseError(e.to_string())
            })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::WhitelistSourceNotFound(format!(
                "Whitelist source {} not found",
                id
            )));
        }

        Ok(())
    }
}
