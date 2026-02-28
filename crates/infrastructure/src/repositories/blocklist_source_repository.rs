use async_trait::async_trait;
use ferrous_dns_application::ports::BlocklistSourceRepository;
use ferrous_dns_domain::{BlocklistSource, DomainError};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{error, instrument};

type BlocklistSourceRow = (
    i64,
    String,
    Option<String>,
    i64,
    Option<String>,
    i64,
    String,
    String,
);

pub struct SqliteBlocklistSourceRepository {
    pool: SqlitePool,
}

impl SqliteBlocklistSourceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_source(row: BlocklistSourceRow) -> BlocklistSource {
        let (id, name, url, group_id, comment, enabled, created_at, updated_at) = row;
        BlocklistSource {
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
impl BlocklistSourceRepository for SqliteBlocklistSourceRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: String,
        url: Option<String>,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<BlocklistSource, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let row = sqlx::query_as::<_, BlocklistSourceRow>(
            "INSERT INTO blocklist_sources (name, url, group_id, comment, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             RETURNING id, name, url, group_id, comment, enabled, created_at, updated_at",
        )
        .bind(&name)
        .bind(&url)
        .bind(group_id)
        .bind(&comment)
        .bind(if enabled { 1i64 } else { 0i64 })
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::InvalidBlocklistSource(format!(
                    "Blocklist source '{}' already exists",
                    name
                ))
            } else {
                error!(error = %e, "Failed to create blocklist source");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        Ok(Self::row_to_source(row))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<BlocklistSource>, DomainError> {
        let row = sqlx::query_as::<_, BlocklistSourceRow>(
            "SELECT id, name, url, group_id, comment, enabled, created_at, updated_at
             FROM blocklist_sources WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query blocklist source by id");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Self::row_to_source))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<BlocklistSource>, DomainError> {
        let rows = sqlx::query_as::<_, BlocklistSourceRow>(
            "SELECT id, name, url, group_id, comment, enabled, created_at, updated_at
             FROM blocklist_sources ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query all blocklist sources");
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
    ) -> Result<BlocklistSource, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let current = self
            .get_by_id(id)
            .await?
            .ok_or(DomainError::BlocklistSourceNotFound(id))?;

        let final_name = name.unwrap_or_else(|| current.name.to_string());
        let final_url: Option<String> = match url {
            Some(u) => u,
            None => current.url.as_ref().map(|s| s.to_string()),
        };
        let final_group_id = group_id.unwrap_or(current.group_id);
        let final_comment: Option<String> =
            comment.or_else(|| current.comment.as_ref().map(|s| s.to_string()));
        let final_enabled = enabled.unwrap_or(current.enabled);

        let row = sqlx::query_as::<_, BlocklistSourceRow>(
            "UPDATE blocklist_sources
             SET name = ?, url = ?, group_id = ?, comment = ?, enabled = ?, updated_at = ?
             WHERE id = ?
             RETURNING id, name, url, group_id, comment, enabled, created_at, updated_at",
        )
        .bind(&final_name)
        .bind(&final_url)
        .bind(final_group_id)
        .bind(&final_comment)
        .bind(if final_enabled { 1i64 } else { 0i64 })
        .bind(&now)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::InvalidBlocklistSource(format!(
                    "Blocklist source '{}' already exists",
                    final_name
                ))
            } else {
                error!(error = %e, "Failed to update blocklist source");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        row.map(Self::row_to_source)
            .ok_or(DomainError::BlocklistSourceNotFound(id))
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM blocklist_sources WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete blocklist source");
                DomainError::DatabaseError(e.to_string())
            })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::BlocklistSourceNotFound(id));
        }

        Ok(())
    }
}
