use async_trait::async_trait;
use ferrous_dns_application::ports::BlocklistSourceRepository;
use ferrous_dns_domain::{BlocklistSource, DomainError};
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use tracing::{error, instrument};

type BlocklistSourceRow = (
    i64,
    String,
    Option<String>,
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

    fn row_to_source(row: BlocklistSourceRow, group_ids: Vec<i64>) -> BlocklistSource {
        let (id, name, url, comment, enabled, created_at, updated_at) = row;
        BlocklistSource {
            id: Some(id),
            name: Arc::from(name.as_str()),
            url: url.map(|s| Arc::from(s.as_str())),
            group_ids,
            comment: comment.map(|s| Arc::from(s.as_str())),
            enabled: enabled != 0,
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }

    async fn fetch_group_ids(&self, source_id: i64) -> Result<Vec<i64>, DomainError> {
        let rows = sqlx::query(
            "SELECT group_id FROM blocklist_source_groups WHERE source_id = ? ORDER BY group_id",
        )
        .bind(source_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch group_ids for blocklist source");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.iter().map(|r| r.get::<i64, _>("group_id")).collect())
    }
}

#[async_trait]
impl BlocklistSourceRepository for SqliteBlocklistSourceRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: String,
        url: Option<String>,
        group_ids: Vec<i64>,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<BlocklistSource, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        // Use first group_id for the legacy column (backward compat)
        let legacy_group_id = group_ids.first().copied().unwrap_or(1);

        let mut tx = self.pool.begin().await.map_err(|e| {
            error!(error = %e, "Failed to begin transaction");
            DomainError::DatabaseError(e.to_string())
        })?;

        let row = sqlx::query_as::<_, BlocklistSourceRow>(
            "INSERT INTO blocklist_sources (name, url, group_id, comment, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             RETURNING id, name, url, comment, enabled, created_at, updated_at",
        )
        .bind(&name)
        .bind(&url)
        .bind(legacy_group_id)
        .bind(&comment)
        .bind(if enabled { 1i64 } else { 0i64 })
        .bind(&now)
        .bind(&now)
        .fetch_one(&mut *tx)
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

        let source_id: i64 = row.0;

        for &gid in &group_ids {
            sqlx::query("INSERT INTO blocklist_source_groups (source_id, group_id) VALUES (?, ?)")
                .bind(source_id)
                .bind(gid)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to insert blocklist_source_groups");
                    DomainError::DatabaseError(e.to_string())
                })?;
        }

        tx.commit().await.map_err(|e| {
            error!(error = %e, "Failed to commit blocklist source creation");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(Self::row_to_source(row, group_ids))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<BlocklistSource>, DomainError> {
        let row = sqlx::query_as::<_, BlocklistSourceRow>(
            "SELECT id, name, url, comment, enabled, created_at, updated_at
             FROM blocklist_sources WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query blocklist source by id");
            DomainError::DatabaseError(e.to_string())
        })?;

        match row {
            None => Ok(None),
            Some(r) => {
                let group_ids = self.fetch_group_ids(r.0).await?;
                Ok(Some(Self::row_to_source(r, group_ids)))
            }
        }
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<BlocklistSource>, DomainError> {
        let rows = sqlx::query_as::<_, BlocklistSourceRow>(
            "SELECT id, name, url, comment, enabled, created_at, updated_at
             FROM blocklist_sources ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query all blocklist sources");
            DomainError::DatabaseError(e.to_string())
        })?;

        let mut sources = Vec::with_capacity(rows.len());
        for row in rows {
            let group_ids = self.fetch_group_ids(row.0).await?;
            sources.push(Self::row_to_source(row, group_ids));
        }
        Ok(sources)
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        url: Option<Option<String>>,
        group_ids: Option<Vec<i64>>,
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
        let final_group_ids = group_ids.unwrap_or_else(|| current.group_ids.clone());
        let final_comment: Option<String> =
            comment.or_else(|| current.comment.as_ref().map(|s| s.to_string()));
        let final_enabled = enabled.unwrap_or(current.enabled);
        let legacy_group_id = final_group_ids.first().copied().unwrap_or(1);

        let mut tx = self.pool.begin().await.map_err(|e| {
            error!(error = %e, "Failed to begin transaction");
            DomainError::DatabaseError(e.to_string())
        })?;

        let row = sqlx::query_as::<_, BlocklistSourceRow>(
            "UPDATE blocklist_sources
             SET name = ?, url = ?, group_id = ?, comment = ?, enabled = ?, updated_at = ?
             WHERE id = ?
             RETURNING id, name, url, comment, enabled, created_at, updated_at",
        )
        .bind(&final_name)
        .bind(&final_url)
        .bind(legacy_group_id)
        .bind(&final_comment)
        .bind(if final_enabled { 1i64 } else { 0i64 })
        .bind(&now)
        .bind(id)
        .fetch_optional(&mut *tx)
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
        })?
        .ok_or(DomainError::BlocklistSourceNotFound(id))?;

        // Replace group assignments atomically
        sqlx::query("DELETE FROM blocklist_source_groups WHERE source_id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete old blocklist_source_groups");
                DomainError::DatabaseError(e.to_string())
            })?;

        for &gid in &final_group_ids {
            sqlx::query("INSERT INTO blocklist_source_groups (source_id, group_id) VALUES (?, ?)")
                .bind(id)
                .bind(gid)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to insert blocklist_source_groups");
                    DomainError::DatabaseError(e.to_string())
                })?;
        }

        tx.commit().await.map_err(|e| {
            error!(error = %e, "Failed to commit blocklist source update");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(Self::row_to_source(row, final_group_ids))
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
