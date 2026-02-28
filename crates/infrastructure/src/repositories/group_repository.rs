use super::client_row_mapper::{row_to_client, ClientRow, CLIENT_SELECT};
use async_trait::async_trait;
use ferrous_dns_application::ports::GroupRepository;
use ferrous_dns_domain::{Client, DomainError, Group};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{error, instrument};

type GroupRow = (i64, String, i64, Option<String>, i64, String, String);

pub struct SqliteGroupRepository {
    pool: SqlitePool,
}

impl SqliteGroupRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_group(row: GroupRow) -> Group {
        let (id, name, enabled, comment, is_default, created_at, updated_at) = row;

        Group {
            id: Some(id),
            name: Arc::from(name.as_str()),
            enabled: enabled != 0,
            comment: comment.map(|s| Arc::from(s.as_str())),
            is_default: is_default != 0,
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }
}

#[async_trait]
impl GroupRepository for SqliteGroupRepository {
    #[instrument(skip(self))]
    async fn create(&self, name: String, comment: Option<String>) -> Result<Group, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let row = sqlx::query_as::<_, GroupRow>(
            "INSERT INTO groups (name, enabled, comment, is_default, created_at, updated_at)
             VALUES (?, 1, ?, 0, ?, ?)
             RETURNING id, name, enabled, comment, is_default, created_at, updated_at",
        )
        .bind(&name)
        .bind(&comment)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::InvalidGroupName(format!("Group '{}' already exists", name))
            } else {
                error!(error = %e, "Failed to create group");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        Ok(Self::row_to_group(row))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<Group>, DomainError> {
        let row = sqlx::query_as::<_, GroupRow>(
            "SELECT id, name, enabled, comment, is_default, created_at, updated_at
             FROM groups WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query group by id");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Self::row_to_group))
    }

    #[instrument(skip(self))]
    async fn get_by_name(&self, name: &str) -> Result<Option<Group>, DomainError> {
        let row = sqlx::query_as::<_, GroupRow>(
            "SELECT id, name, enabled, comment, is_default, created_at, updated_at
             FROM groups WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query group by name");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Self::row_to_group))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<Group>, DomainError> {
        let rows = sqlx::query_as::<_, GroupRow>(
            "SELECT id, name, enabled, comment, is_default, created_at, updated_at
             FROM groups ORDER BY is_default DESC, name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query all groups");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Self::row_to_group).collect())
    }

    #[instrument(skip(self))]
    async fn get_all_with_client_counts(&self) -> Result<Vec<(Group, u64)>, DomainError> {
        let rows = sqlx::query_as::<_, (i64, String, i64, Option<String>, i64, String, String, i64)>(
            "SELECT g.id, g.name, g.enabled, g.comment, g.is_default, g.created_at, g.updated_at,
                    COUNT(c.id) as client_count
             FROM groups g
             LEFT JOIN clients c ON c.group_id = g.id
             GROUP BY g.id
             ORDER BY g.is_default DESC, g.name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query groups with client counts");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows
            .into_iter()
            .map(
                |(id, name, enabled, comment, is_default, created_at, updated_at, count)| {
                    let group = Group {
                        id: Some(id),
                        name: Arc::from(name.as_str()),
                        enabled: enabled != 0,
                        comment: comment.map(|s| Arc::from(s.as_str())),
                        is_default: is_default != 0,
                        created_at: Some(created_at),
                        updated_at: Some(updated_at),
                    };
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
    ) -> Result<Group, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let current = self
            .get_by_id(id)
            .await?
            .ok_or(DomainError::GroupNotFound(id))?;

        let final_name = name.unwrap_or_else(|| current.name.to_string());
        let final_enabled = enabled.unwrap_or(current.enabled);
        let final_comment = comment.or_else(|| current.comment.as_ref().map(|s| s.to_string()));

        let row = sqlx::query_as::<_, GroupRow>(
            "UPDATE groups SET name = ?, enabled = ?, comment = ?, updated_at = ?
             WHERE id = ?
             RETURNING id, name, enabled, comment, is_default, created_at, updated_at",
        )
        .bind(&final_name)
        .bind(if final_enabled { 1 } else { 0 })
        .bind(&final_comment)
        .bind(&now)
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::InvalidGroupName(format!("Group '{}' already exists", final_name))
            } else {
                error!(error = %e, "Failed to update group");
                DomainError::DatabaseError(e.to_string())
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
            .map_err(|e| {
                if e.to_string().contains("FOREIGN KEY constraint failed") {
                    DomainError::GroupHasAssignedClients(0)
                } else {
                    error!(error = %e, "Failed to delete group");
                    DomainError::DatabaseError(e.to_string())
                }
            })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::GroupNotFound(id));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_clients_in_group(&self, group_id: i64) -> Result<Vec<Client>, DomainError> {
        let rows = sqlx::query_as::<_, ClientRow>(&format!(
            "{} WHERE group_id = ? ORDER BY last_seen DESC",
            CLIENT_SELECT
        ))
        .bind(group_id)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query clients in group");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().filter_map(row_to_client).collect())
    }

    #[instrument(skip(self))]
    async fn count_clients_in_group(&self, group_id: i64) -> Result<u64, DomainError> {
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM clients WHERE group_id = ?")
            .bind(group_id)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to count clients in group");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(count.0 as u64)
    }
}
