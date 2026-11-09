use super::client_row_mapper::{row_to_client, ClientRow, CLIENT_SELECT_BY_GROUP};
use crate::repositories::{db_err, is_unique_violation, sql_now};
use async_trait::async_trait;
use ferrous_dns_application::ports::GroupRepository;
use ferrous_dns_domain::{Client, DomainError, Group};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::instrument;

type GroupRow = (
    i64,
    String,
    bool,
    Option<String>,
    bool,
    bool,
    String,
    String,
);

const GROUP_COLUMNS: &str =
    "id, name, enabled, comment, is_default, malware_detection_enabled, created_at, updated_at";

pub struct SqliteGroupRepository {
    pool: SqlitePool,
}

impl SqliteGroupRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_group(row: GroupRow) -> Group {
        let (
            id,
            name,
            enabled,
            comment,
            is_default,
            malware_detection_enabled,
            created_at,
            updated_at,
        ) = row;

        Group {
            id: Some(id),
            name: Arc::from(name.as_str()),
            enabled,
            comment: comment.map(|s| Arc::from(s.as_str())),
            is_default,
            malware_detection_enabled,
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }
}

#[async_trait]
impl GroupRepository for SqliteGroupRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: String,
        comment: Option<String>,
        enabled: bool,
        malware_detection_enabled: bool,
    ) -> Result<Group, DomainError> {
        let now = sql_now();

        let row = sqlx::query_as::<_, GroupRow>(&format!(
            "INSERT INTO groups
                 (name, enabled, comment, is_default, malware_detection_enabled, created_at, updated_at)
             VALUES (?, ?, ?, 0, ?, ?, ?)
             RETURNING {GROUP_COLUMNS}"
        ))
        .bind(&name)
        .bind(enabled)
        .bind(&comment)
        .bind(malware_detection_enabled)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::AlreadyExists(format!("Group '{name}' already exists"))
            } else {
                db_err("Failed to create group")(e)
            }
        })?;

        Ok(Self::row_to_group(row))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<Group>, DomainError> {
        let row = sqlx::query_as::<_, GroupRow>(&format!(
            "SELECT {GROUP_COLUMNS} FROM groups WHERE id = ?"
        ))
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query group by id"))?;

        Ok(row.map(Self::row_to_group))
    }

    #[instrument(skip(self))]
    async fn get_by_name(&self, name: &str) -> Result<Option<Group>, DomainError> {
        let row = sqlx::query_as::<_, GroupRow>(&format!(
            "SELECT {GROUP_COLUMNS} FROM groups WHERE name = ?"
        ))
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(db_err("Failed to query group by name"))?;

        Ok(row.map(Self::row_to_group))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<Group>, DomainError> {
        let rows = sqlx::query_as::<_, GroupRow>(&format!(
            "SELECT {GROUP_COLUMNS} FROM groups ORDER BY is_default DESC, name ASC"
        ))
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query all groups"))?;

        Ok(rows.into_iter().map(Self::row_to_group).collect())
    }

    #[instrument(skip(self))]
    async fn get_all_with_client_counts(&self) -> Result<Vec<(Group, u64)>, DomainError> {
        let rows = sqlx::query_as::<
            _,
            (
                i64,
                String,
                bool,
                Option<String>,
                bool,
                bool,
                String,
                String,
                i64,
            ),
        >(
            "SELECT g.id, g.name, g.enabled, g.comment, g.is_default, g.malware_detection_enabled,
                    g.created_at, g.updated_at, COUNT(c.id) as client_count
             FROM groups g
             LEFT JOIN clients c ON c.group_id = g.id
             GROUP BY g.id
             ORDER BY g.is_default DESC, g.name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(db_err("Failed to query groups with client counts"))?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    id,
                    name,
                    enabled,
                    comment,
                    is_default,
                    malware_detection_enabled,
                    created_at,
                    updated_at,
                    count,
                )| {
                    let group = Self::row_to_group((
                        id,
                        name,
                        enabled,
                        comment,
                        is_default,
                        malware_detection_enabled,
                        created_at,
                        updated_at,
                    ));
                    (group, count as u64)
                },
            )
            .collect())
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        enabled: Option<bool>,
        comment: Option<String>,
        malware_detection_enabled: Option<bool>,
    ) -> Result<Group, DomainError> {
        let row = sqlx::query_as::<_, GroupRow>(&format!(
            "UPDATE groups
             SET name = COALESCE(?, name),
                 enabled = COALESCE(?, enabled),
                 comment = COALESCE(?, comment),
                 malware_detection_enabled = COALESCE(?, malware_detection_enabled),
                 updated_at = ?
             WHERE id = ?
             RETURNING {GROUP_COLUMNS}"
        ))
        .bind(&name)
        .bind(enabled)
        .bind(&comment)
        .bind(malware_detection_enabled)
        .bind(sql_now())
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::AlreadyExists(format!(
                    "Group '{}' already exists",
                    name.as_deref().unwrap_or_default()
                ))
            } else {
                db_err("Failed to update group")(e)
            }
        })?;

        row.map(Self::row_to_group)
            .ok_or(DomainError::GroupNotFound(id))
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM groups WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete group"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::GroupNotFound(id));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_clients_in_group(&self, group_id: i64) -> Result<Vec<Client>, DomainError> {
        let rows = sqlx::query_as::<_, ClientRow>(CLIENT_SELECT_BY_GROUP)
            .bind(group_id)
            .fetch_all(&self.pool)
            .await
            .map_err(db_err("Failed to query clients in group"))?;

        Ok(rows.into_iter().filter_map(row_to_client).collect())
    }

    #[instrument(skip(self))]
    async fn count_clients_in_group(&self, group_id: i64) -> Result<u64, DomainError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM clients WHERE group_id = ?")
            .bind(group_id)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err("Failed to count clients in group"))?;

        Ok(count.0 as u64)
    }

    #[instrument(skip(self))]
    async fn count_doh_ids_in_group(&self, group_id: i64) -> Result<u64, DomainError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM doh_ids WHERE group_id = ?")
            .bind(group_id)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err("Failed to count DoH IDs in group"))?;

        Ok(count.0 as u64)
    }
}
