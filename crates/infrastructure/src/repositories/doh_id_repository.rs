use crate::repositories::{db_err, is_fk_violation, is_unique_violation, sql_now};
use async_trait::async_trait;
use ferrous_dns_application::ports::DohIdRepository;
use ferrous_dns_domain::{DohId, DomainError};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::instrument;

type DohIdRow = (i64, String, String, i64, Option<String>, String, String);

const DOH_ID_COLUMNS: &str = "id, name, client_id, group_id, comment, created_at, updated_at";

pub struct SqliteDohIdRepository {
    pool: SqlitePool,
}

impl SqliteDohIdRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_doh_id(row: DohIdRow) -> DohId {
        let (id, name, client_id, group_id, comment, created_at, updated_at) = row;

        DohId {
            id: Some(id),
            name: Arc::from(name.as_str()),
            client_id: Arc::from(client_id.as_str()),
            group_id,
            comment: comment.map(|s| Arc::from(s.as_str())),
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }

    fn conflict_error(e: &sqlx::Error, name: &str, client_id: Option<&str>) -> DomainError {
        if matches!(e, sqlx::Error::Database(db) if db.message().contains("doh_ids.client_id")) {
            match client_id {
                Some(cid) => {
                    DomainError::DohIdConflict(format!("DoH client ID '{cid}' already exists"))
                }
                None => DomainError::DohIdConflict("DoH client ID already exists".to_string()),
            }
        } else {
            DomainError::DohIdConflict(format!("DoH ID name '{name}' already exists"))
        }
    }
}

#[async_trait]
impl DohIdRepository for SqliteDohIdRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: String,
        client_id: String,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<DohId, DomainError> {
        let now = sql_now();

        let row = sqlx::query_as::<_, DohIdRow>(&format!(
            "INSERT INTO doh_ids (name, client_id, group_id, comment, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             RETURNING {DOH_ID_COLUMNS}"
        ))
        .bind(&name)
        .bind(&client_id)
        .bind(group_id)
        .bind(&comment)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                Self::conflict_error(&e, &name, Some(&client_id))
            } else if is_fk_violation(&e) {
                DomainError::GroupNotFound(group_id)
            } else {
                db_err("Failed to create DoH ID")(e)
            }
        })?;

        Ok(Self::row_to_doh_id(row))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<DohId>, DomainError> {
        let row = sqlx::query_as::<_, DohIdRow>(&format!(
            "SELECT {DOH_ID_COLUMNS} FROM doh_ids WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query DoH ID by id"))?;

        Ok(row.map(Self::row_to_doh_id))
    }

    #[instrument(skip(self))]
    async fn get_by_client_id(&self, client_id: &str) -> Result<Option<DohId>, DomainError> {
        let row = sqlx::query_as::<_, DohIdRow>(&format!(
            "SELECT {DOH_ID_COLUMNS} FROM doh_ids WHERE client_id = ?"
        ))
        .bind(client_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query DoH ID by client_id"))?;

        Ok(row.map(Self::row_to_doh_id))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<DohId>, DomainError> {
        let rows = sqlx::query_as::<_, DohIdRow>(&format!(
            "SELECT {DOH_ID_COLUMNS} FROM doh_ids ORDER BY created_at DESC, id DESC"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query all DoH IDs"))?;

        Ok(rows.into_iter().map(Self::row_to_doh_id).collect())
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        id: i64,
        name: String,
        client_id: Option<String>,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<DohId, DomainError> {
        let row = sqlx::query_as::<_, DohIdRow>(&format!(
            "UPDATE doh_ids
             SET name = ?,
                 client_id = COALESCE(?, client_id),
                 group_id = ?,
                 comment = ?,
                 updated_at = ?
             WHERE id = ?
             RETURNING {DOH_ID_COLUMNS}"
        ))
        .bind(&name)
        .bind(&client_id)
        .bind(group_id)
        .bind(&comment)
        .bind(sql_now())
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                Self::conflict_error(&e, &name, client_id.as_deref())
            } else if is_fk_violation(&e) {
                DomainError::GroupNotFound(group_id)
            } else {
                db_err("Failed to update DoH ID")(e)
            }
        })?;

        row.map(Self::row_to_doh_id)
            .ok_or(DomainError::DohIdNotFound(id))
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM doh_ids WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete DoH ID"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::DohIdNotFound(id));
        }

        Ok(())
    }
}
