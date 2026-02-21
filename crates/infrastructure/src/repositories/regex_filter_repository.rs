use async_trait::async_trait;
use fancy_regex::Regex;
use ferrous_dns_application::ports::RegexFilterRepository;
use ferrous_dns_domain::{DomainAction, DomainError, RegexFilter};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{error, instrument};

type RegexFilterRow = (
    i64,
    String,
    String,
    String,
    i64,
    Option<String>,
    i64,
    String,
    String,
);

pub struct SqliteRegexFilterRepository {
    pool: SqlitePool,
}

impl SqliteRegexFilterRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_filter(row: RegexFilterRow) -> RegexFilter {
        let (id, name, pattern, action, group_id, comment, enabled, created_at, updated_at) = row;
        RegexFilter {
            id: Some(id),
            name: Arc::from(name.as_str()),
            pattern: Arc::from(pattern.as_str()),
            action: action.parse::<DomainAction>().unwrap_or(DomainAction::Deny),
            group_id,
            comment: comment.map(|s| Arc::from(s.as_str())),
            enabled: enabled != 0,
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }

    fn validate_regex_syntax(pattern: &str) -> Result<(), DomainError> {
        Regex::new(pattern).map(|_| ()).map_err(|e| {
            DomainError::InvalidRegexFilter(format!("Invalid regex pattern '{}': {}", pattern, e))
        })
    }
}

#[async_trait]
impl RegexFilterRepository for SqliteRegexFilterRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: String,
        pattern: String,
        action: DomainAction,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<RegexFilter, DomainError> {
        Self::validate_regex_syntax(&pattern)?;

        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let result = sqlx::query(
            "INSERT INTO regex_filters (name, pattern, action, group_id, comment, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&name)
        .bind(&pattern)
        .bind(action.to_str())
        .bind(group_id)
        .bind(&comment)
        .bind(if enabled { 1i64 } else { 0i64 })
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::InvalidRegexFilter(format!(
                    "Regex filter '{}' already exists",
                    name
                ))
            } else {
                error!(error = %e, "Failed to create regex filter");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        let id = result.last_insert_rowid();

        self.get_by_id(id).await?.ok_or_else(|| {
            DomainError::DatabaseError("Failed to fetch created regex filter".to_string())
        })
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<RegexFilter>, DomainError> {
        let row = sqlx::query_as::<_, RegexFilterRow>(
            "SELECT id, name, pattern, action, group_id, comment, enabled, created_at, updated_at
             FROM regex_filters WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query regex filter by id");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Self::row_to_filter))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<RegexFilter>, DomainError> {
        let rows = sqlx::query_as::<_, RegexFilterRow>(
            "SELECT id, name, pattern, action, group_id, comment, enabled, created_at, updated_at
             FROM regex_filters ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query all regex filters");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Self::row_to_filter).collect())
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        pattern: Option<String>,
        action: Option<DomainAction>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<RegexFilter, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let current = self
            .get_by_id(id)
            .await?
            .ok_or(DomainError::RegexFilterNotFound(id))?;

        let final_name = name.unwrap_or_else(|| current.name.to_string());
        let final_pattern = pattern.unwrap_or_else(|| current.pattern.to_string());
        let final_action = action.unwrap_or(current.action);
        let final_group_id = group_id.unwrap_or(current.group_id);
        let final_comment: Option<String> =
            comment.or_else(|| current.comment.as_ref().map(|s| s.to_string()));
        let final_enabled = enabled.unwrap_or(current.enabled);

        Self::validate_regex_syntax(&final_pattern)?;

        let result = sqlx::query(
            "UPDATE regex_filters
             SET name = ?, pattern = ?, action = ?, group_id = ?, comment = ?, enabled = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(&final_name)
        .bind(&final_pattern)
        .bind(final_action.to_str())
        .bind(final_group_id)
        .bind(&final_comment)
        .bind(if final_enabled { 1i64 } else { 0i64 })
        .bind(&now)
        .bind(id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::InvalidRegexFilter(format!(
                    "Regex filter '{}' already exists",
                    final_name
                ))
            } else {
                error!(error = %e, "Failed to update regex filter");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::RegexFilterNotFound(id));
        }

        self.get_by_id(id).await?.ok_or_else(|| {
            DomainError::DatabaseError("Failed to fetch updated regex filter".to_string())
        })
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM regex_filters WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete regex filter");
                DomainError::DatabaseError(e.to_string())
            })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::RegexFilterNotFound(id));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_enabled(&self) -> Result<Vec<RegexFilter>, DomainError> {
        let rows = sqlx::query_as::<_, RegexFilterRow>(
            "SELECT id, name, pattern, action, group_id, comment, enabled, created_at, updated_at
             FROM regex_filters WHERE enabled = 1 ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query enabled regex filters");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Self::row_to_filter).collect())
    }
}
