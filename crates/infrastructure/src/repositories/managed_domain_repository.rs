use async_trait::async_trait;
use ferrous_dns_application::ports::ManagedDomainRepository;
use ferrous_dns_domain::{DomainAction, DomainError, ManagedDomain};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{error, instrument};

type ManagedDomainRow = (
    i64,
    String,
    String,
    String,
    i64,
    Option<String>,
    i64,
    Option<String>,
    String,
    String,
);

pub struct SqliteManagedDomainRepository {
    pool: SqlitePool,
}

impl SqliteManagedDomainRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_domain(row: ManagedDomainRow) -> ManagedDomain {
        let (
            id,
            name,
            domain,
            action,
            group_id,
            comment,
            enabled,
            service_id,
            created_at,
            updated_at,
        ) = row;
        ManagedDomain {
            id: Some(id),
            name: Arc::from(name.as_str()),
            domain: Arc::from(domain.as_str()),
            action: action.parse::<DomainAction>().unwrap_or(DomainAction::Deny),
            group_id,
            comment: comment.map(|s| Arc::from(s.as_str())),
            enabled: enabled != 0,
            service_id: service_id.map(|s| Arc::from(s.as_str())),
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }
}

#[async_trait]
impl ManagedDomainRepository for SqliteManagedDomainRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        name: String,
        domain: String,
        action: DomainAction,
        group_id: i64,
        comment: Option<String>,
        enabled: bool,
    ) -> Result<ManagedDomain, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let result = sqlx::query(
            "INSERT INTO managed_domains (name, domain, action, group_id, comment, enabled, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&name)
        .bind(&domain)
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
                DomainError::InvalidManagedDomain(format!(
                    "Managed domain '{}' already exists",
                    name
                ))
            } else {
                error!(error = %e, "Failed to create managed domain");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        let id = result.last_insert_rowid();

        self.get_by_id(id).await?.ok_or_else(|| {
            DomainError::DatabaseError("Failed to fetch created managed domain".to_string())
        })
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<ManagedDomain>, DomainError> {
        let row = sqlx::query_as::<_, ManagedDomainRow>(
            "SELECT id, name, domain, action, group_id, comment, enabled, service_id, created_at, updated_at
             FROM managed_domains WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query managed domain by id");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Self::row_to_domain))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<ManagedDomain>, DomainError> {
        let rows = sqlx::query_as::<_, ManagedDomainRow>(
            "SELECT id, name, domain, action, group_id, comment, enabled, service_id, created_at, updated_at
             FROM managed_domains ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query all managed domains");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Self::row_to_domain).collect())
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        id: i64,
        name: Option<String>,
        domain: Option<String>,
        action: Option<DomainAction>,
        group_id: Option<i64>,
        comment: Option<String>,
        enabled: Option<bool>,
    ) -> Result<ManagedDomain, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let current = self
            .get_by_id(id)
            .await?
            .ok_or(DomainError::ManagedDomainNotFound(id))?;

        let final_name = name.unwrap_or_else(|| current.name.to_string());
        let final_domain = domain.unwrap_or_else(|| current.domain.to_string());
        let final_action = action.unwrap_or(current.action);
        let final_group_id = group_id.unwrap_or(current.group_id);
        let final_comment: Option<String> =
            comment.or_else(|| current.comment.as_ref().map(|s| s.to_string()));
        let final_enabled = enabled.unwrap_or(current.enabled);

        let result = sqlx::query(
            "UPDATE managed_domains
             SET name = ?, domain = ?, action = ?, group_id = ?, comment = ?, enabled = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(&final_name)
        .bind(&final_domain)
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
                DomainError::InvalidManagedDomain(format!(
                    "Managed domain '{}' already exists",
                    final_name
                ))
            } else {
                error!(error = %e, "Failed to update managed domain");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::ManagedDomainNotFound(id));
        }

        self.get_by_id(id).await?.ok_or_else(|| {
            DomainError::DatabaseError("Failed to fetch updated managed domain".to_string())
        })
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM managed_domains WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete managed domain");
                DomainError::DatabaseError(e.to_string())
            })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::ManagedDomainNotFound(id));
        }

        Ok(())
    }

    #[instrument(skip(self, domains))]
    async fn bulk_create_for_service(
        &self,
        service_id: &str,
        group_id: i64,
        domains: Vec<(String, String)>,
    ) -> Result<usize, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let mut count = 0usize;

        for (name, domain) in &domains {
            let result = sqlx::query(
                "INSERT OR IGNORE INTO managed_domains
                 (name, domain, action, group_id, comment, enabled, service_id, created_at, updated_at)
                 VALUES (?, ?, 'deny', ?, NULL, 1, ?, ?, ?)",
            )
            .bind(name)
            .bind(domain)
            .bind(group_id)
            .bind(service_id)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to bulk create managed domain");
                DomainError::DatabaseError(e.to_string())
            })?;

            if result.rows_affected() > 0 {
                count += 1;
            }
        }

        Ok(count)
    }

    #[instrument(skip(self))]
    async fn delete_by_service(&self, service_id: &str, group_id: i64) -> Result<u64, DomainError> {
        let result =
            sqlx::query("DELETE FROM managed_domains WHERE service_id = ? AND group_id = ?")
                .bind(service_id)
                .bind(group_id)
                .execute(&self.pool)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to delete managed domains by service");
                    DomainError::DatabaseError(e.to_string())
                })?;

        Ok(result.rows_affected())
    }

    #[instrument(skip(self))]
    async fn delete_all_by_service(&self, service_id: &str) -> Result<u64, DomainError> {
        let result = sqlx::query("DELETE FROM managed_domains WHERE service_id = ?")
            .bind(service_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete all managed domains by service");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(result.rows_affected())
    }
}
