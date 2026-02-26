use async_trait::async_trait;
use ferrous_dns_application::ports::CustomServiceRepository;
use ferrous_dns_domain::{CustomService, DomainError};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{error, instrument};

pub struct SqliteCustomServiceRepository {
    pool: SqlitePool,
}

impl SqliteCustomServiceRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_entity(row: (i64, String, String, String, String, String, String)) -> CustomService {
        let (id, service_id, name, category_name, domains_json, created_at, updated_at) = row;
        let raw_domains: Vec<String> = serde_json::from_str(&domains_json).unwrap_or_default();
        let domains: Vec<Arc<str>> = raw_domains
            .into_iter()
            .map(|d| Arc::from(d.as_str()))
            .collect();

        CustomService {
            id: Some(id),
            service_id: Arc::from(service_id.as_str()),
            name: Arc::from(name.as_str()),
            category_name: Arc::from(category_name.as_str()),
            domains,
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }
}

#[async_trait]
impl CustomServiceRepository for SqliteCustomServiceRepository {
    #[instrument(skip(self, domains))]
    async fn create(
        &self,
        service_id: &str,
        name: &str,
        category_name: &str,
        domains: &[String],
    ) -> Result<CustomService, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let domains_json = serde_json::to_string(domains)
            .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        let result = sqlx::query(
            "INSERT INTO custom_services (service_id, name, category_name, domains, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(service_id)
        .bind(name)
        .bind(category_name)
        .bind(&domains_json)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::CustomServiceAlreadyExists(service_id.to_string())
            } else {
                error!(error = %e, "Failed to create custom service");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        let id = result.last_insert_rowid();
        let domains_arc: Vec<Arc<str>> = domains.iter().map(|d| Arc::from(d.as_str())).collect();

        Ok(CustomService {
            id: Some(id),
            service_id: Arc::from(service_id),
            name: Arc::from(name),
            category_name: Arc::from(category_name),
            domains: domains_arc,
            created_at: Some(now.clone()),
            updated_at: Some(now),
        })
    }

    #[instrument(skip(self))]
    async fn get_by_service_id(
        &self,
        service_id: &str,
    ) -> Result<Option<CustomService>, DomainError> {
        let row = sqlx::query_as::<_, (i64, String, String, String, String, String, String)>(
            "SELECT id, service_id, name, category_name, domains, created_at, updated_at
             FROM custom_services WHERE service_id = ?",
        )
        .bind(service_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query custom service by service_id");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Self::row_to_entity))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<CustomService>, DomainError> {
        let rows = sqlx::query_as::<_, (i64, String, String, String, String, String, String)>(
            "SELECT id, service_id, name, category_name, domains, created_at, updated_at
             FROM custom_services ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query all custom services");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Self::row_to_entity).collect())
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        service_id: &str,
        name: Option<String>,
        category_name: Option<String>,
        domains: Option<Vec<String>>,
    ) -> Result<CustomService, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let current = self
            .get_by_service_id(service_id)
            .await?
            .ok_or_else(|| DomainError::CustomServiceNotFound(service_id.to_string()))?;

        let final_name = name.unwrap_or_else(|| current.name.to_string());
        let final_category = category_name.unwrap_or_else(|| current.category_name.to_string());
        let final_domains: Vec<String> =
            domains.unwrap_or_else(|| current.domains.iter().map(|d| d.to_string()).collect());
        let domains_json = serde_json::to_string(&final_domains)
            .map_err(|e| DomainError::DatabaseError(e.to_string()))?;

        let result = sqlx::query(
            "UPDATE custom_services
             SET name = ?, category_name = ?, domains = ?, updated_at = ?
             WHERE service_id = ?",
        )
        .bind(&final_name)
        .bind(&final_category)
        .bind(&domains_json)
        .bind(&now)
        .bind(service_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to update custom service");
            DomainError::DatabaseError(e.to_string())
        })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::CustomServiceNotFound(service_id.to_string()));
        }

        let domains_arc: Vec<Arc<str>> = final_domains
            .iter()
            .map(|d| Arc::from(d.as_str()))
            .collect();

        Ok(CustomService {
            id: current.id,
            service_id: Arc::from(service_id),
            name: Arc::from(final_name.as_str()),
            category_name: Arc::from(final_category.as_str()),
            domains: domains_arc,
            created_at: current.created_at,
            updated_at: Some(now),
        })
    }

    #[instrument(skip(self))]
    async fn delete(&self, service_id: &str) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM custom_services WHERE service_id = ?")
            .bind(service_id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete custom service");
                DomainError::DatabaseError(e.to_string())
            })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::CustomServiceNotFound(service_id.to_string()));
        }

        Ok(())
    }
}
