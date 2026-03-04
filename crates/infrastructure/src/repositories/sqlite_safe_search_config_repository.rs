use async_trait::async_trait;
use ferrous_dns_application::ports::SafeSearchConfigRepository;
use ferrous_dns_domain::{DomainError, SafeSearchConfig, SafeSearchEngine, YouTubeMode};
use sqlx::SqlitePool;
use tracing::warn;

pub struct SqliteSafeSearchConfigRepository {
    pool: SqlitePool,
}

impl SqliteSafeSearchConfigRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_config(
        id: i64,
        group_id: i64,
        engine_str: String,
        enabled: i64,
        youtube_mode_str: String,
        created_at: String,
        updated_at: String,
    ) -> Option<SafeSearchConfig> {
        let engine = engine_str.parse::<SafeSearchEngine>().map_err(|_| {
            warn!(engine = %engine_str, "Unrecognised Safe Search engine in database, skipping row");
        }).ok()?;
        let youtube_mode = youtube_mode_str.parse::<YouTubeMode>().unwrap_or_else(|_| {
            warn!(
                youtube_mode = %youtube_mode_str,
                "Unrecognised youtube_mode in database, defaulting to strict"
            );
            YouTubeMode::default()
        });
        Some(SafeSearchConfig {
            id: Some(id),
            group_id,
            engine,
            enabled: enabled != 0,
            youtube_mode,
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        })
    }
}

#[async_trait]
impl SafeSearchConfigRepository for SqliteSafeSearchConfigRepository {
    async fn get_all(&self) -> Result<Vec<SafeSearchConfig>, DomainError> {
        let rows = sqlx::query_as::<_, (i64, i64, String, i64, String, String, String)>(
            "SELECT id, group_id, engine, enabled, youtube_mode, created_at, updated_at
             FROM safe_search_configs
             ORDER BY group_id, engine",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .filter_map(
                |(id, group_id, engine, enabled, yt_mode, created, updated)| {
                    Self::row_to_config(id, group_id, engine, enabled, yt_mode, created, updated)
                },
            )
            .collect())
    }

    async fn get_by_group(&self, group_id: i64) -> Result<Vec<SafeSearchConfig>, DomainError> {
        let rows = sqlx::query_as::<_, (i64, i64, String, i64, String, String, String)>(
            "SELECT id, group_id, engine, enabled, youtube_mode, created_at, updated_at
             FROM safe_search_configs
             WHERE group_id = ?
             ORDER BY engine",
        )
        .bind(group_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        Ok(rows
            .into_iter()
            .filter_map(
                |(id, group_id, engine, enabled, yt_mode, created, updated)| {
                    Self::row_to_config(id, group_id, engine, enabled, yt_mode, created, updated)
                },
            )
            .collect())
    }

    async fn upsert(
        &self,
        group_id: i64,
        engine: SafeSearchEngine,
        enabled: bool,
        youtube_mode: YouTubeMode,
    ) -> Result<SafeSearchConfig, DomainError> {
        let now = chrono::Utc::now().to_rfc3339();
        let engine_str = engine.to_str();
        let youtube_mode_str = youtube_mode.to_str();
        let enabled_int = i64::from(enabled);

        let row = sqlx::query_as::<_, (i64, i64, String, i64, String, String, String)>(
            "INSERT INTO safe_search_configs (group_id, engine, enabled, youtube_mode, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(group_id, engine) DO UPDATE SET
               enabled      = excluded.enabled,
               youtube_mode = excluded.youtube_mode,
               updated_at   = excluded.updated_at
             RETURNING id, group_id, engine, enabled, youtube_mode, created_at, updated_at",
        )
        .bind(group_id)
        .bind(engine_str)
        .bind(enabled_int)
        .bind(youtube_mode_str)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        Self::row_to_config(row.0, row.1, row.2, row.3, row.4, row.5, row.6)
            .ok_or_else(|| DomainError::DatabaseError("Invalid safe search config row".into()))
    }

    async fn delete_by_group(&self, group_id: i64) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM safe_search_configs WHERE group_id = ?")
            .bind(group_id)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::DatabaseError(e.to_string()))?;
        Ok(())
    }
}
