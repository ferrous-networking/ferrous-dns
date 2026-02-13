use async_trait::async_trait;
use ferrous_dns_application::ports::ClientSubnetRepository;
use ferrous_dns_domain::{ClientSubnet, DomainError};
use sqlx::SqlitePool;
use std::sync::Arc;
use tracing::{error, instrument};

type SubnetRow = (i64, String, i64, Option<String>, String, String);

pub struct SqliteClientSubnetRepository {
    pool: SqlitePool,
}

impl SqliteClientSubnetRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    fn row_to_subnet(row: SubnetRow) -> ClientSubnet {
        let (id, subnet_cidr, group_id, comment, created_at, updated_at) = row;

        ClientSubnet {
            id: Some(id),
            subnet_cidr: Arc::from(subnet_cidr.as_str()),
            group_id,
            comment: comment.map(|s| Arc::from(s.as_str())),
            created_at: Some(created_at),
            updated_at: Some(updated_at),
        }
    }
}

#[async_trait]
impl ClientSubnetRepository for SqliteClientSubnetRepository {
    #[instrument(skip(self))]
    async fn create(
        &self,
        subnet_cidr: String,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let result = sqlx::query(
            "INSERT INTO client_subnets (subnet_cidr, group_id, comment, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&subnet_cidr)
        .bind(group_id)
        .bind(&comment)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint failed") {
                DomainError::SubnetConflict(format!("Subnet '{}' already exists", subnet_cidr))
            } else if e.to_string().contains("FOREIGN KEY constraint failed") {
                DomainError::GroupNotFound(format!("Group {} not found", group_id))
            } else {
                error!(error = %e, "Failed to create client subnet");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        let id = result.last_insert_rowid();

        self.get_by_id(id)
            .await?
            .ok_or_else(|| DomainError::DatabaseError("Failed to fetch created subnet".to_string()))
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<ClientSubnet>, DomainError> {
        let row = sqlx::query_as::<_, SubnetRow>(
            "SELECT id, subnet_cidr, group_id, comment, created_at, updated_at
             FROM client_subnets WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query subnet by id");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(Self::row_to_subnet))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<ClientSubnet>, DomainError> {
        let rows = sqlx::query_as::<_, SubnetRow>(
            "SELECT id, subnet_cidr, group_id, comment, created_at, updated_at
             FROM client_subnets
             ORDER BY created_at DESC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to query all subnets");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(Self::row_to_subnet).collect())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM client_subnets WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete subnet");
                DomainError::DatabaseError(e.to_string())
            })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::SubnetNotFound(format!(
                "Subnet {} not found",
                id
            )));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn exists(&self, subnet_cidr: &str) -> Result<bool, DomainError> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM client_subnets WHERE subnet_cidr = ?")
                .bind(subnet_cidr)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to check subnet existence");
                    DomainError::DatabaseError(e.to_string())
                })?;

        Ok(count.0 > 0)
    }
}
