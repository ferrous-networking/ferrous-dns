use crate::repositories::{db_err, is_fk_violation, is_unique_violation, sql_now};
use async_trait::async_trait;
use ferrous_dns_application::ports::ClientSubnetRepository;
use ferrous_dns_domain::{ClientSubnet, DomainError};
use ipnetwork::IpNetwork;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{instrument, warn};

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
        network: IpNetwork,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError> {
        let now = sql_now();
        let subnet_cidr = network.to_string();

        let row = sqlx::query_as::<_, SubnetRow>(
            "INSERT INTO client_subnets (subnet_cidr, group_id, comment, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?)
             RETURNING id, subnet_cidr, group_id, comment, created_at, updated_at",
        )
        .bind(&subnet_cidr)
        .bind(group_id)
        .bind(&comment)
        .bind(&now)
        .bind(&now)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                DomainError::SubnetConflict(format!("Subnet '{subnet_cidr}' already exists"))
            } else if is_fk_violation(&e) {
                DomainError::GroupNotFound(group_id)
            } else {
                db_err("Failed to create client subnet")(e)
            }
        })?;

        Ok(Self::row_to_subnet(row))
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
        .map_err(db_err("Failed to query subnet by id"))?;

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
        .map_err(db_err("Failed to query all subnets"))?;

        Ok(rows.into_iter().map(Self::row_to_subnet).collect())
    }

    #[instrument(skip(self))]
    async fn update(
        &self,
        id: i64,
        group_id: i64,
        comment: Option<String>,
    ) -> Result<ClientSubnet, DomainError> {
        let row = sqlx::query_as::<_, SubnetRow>(
            "UPDATE client_subnets SET group_id = ?, comment = ?, updated_at = ?
             WHERE id = ?
             RETURNING id, subnet_cidr, group_id, comment, created_at, updated_at",
        )
        .bind(group_id)
        .bind(&comment)
        .bind(sql_now())
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| {
            if is_fk_violation(&e) {
                DomainError::GroupNotFound(group_id)
            } else {
                db_err("Failed to update client subnet")(e)
            }
        })?;

        row.map(Self::row_to_subnet)
            .ok_or_else(|| DomainError::SubnetNotFound(format!("Subnet {id} not found")))
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM client_subnets WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete subnet"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::SubnetNotFound(format!(
                "Subnet {id} not found"
            )));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn exists(&self, network: IpNetwork) -> Result<bool, DomainError> {
        let count: (i64,) =
            sqlx::query_as("SELECT COUNT(*) FROM client_subnets WHERE subnet_cidr = ?")
                .bind(network.to_string())
                .fetch_one(&self.pool)
                .await
                .map_err(db_err("Failed to check subnet existence"))?;

        Ok(count.0 > 0)
    }
}

/// Rewrites stored subnets to the canonical text `ClientSubnet::parse_cidr`
/// produces, so rows written before canonicalisation compare equal to new
/// ones. Of several rows naming the same network the oldest (lowest id)
/// survives. SQL alone can't canonicalise IPv6 text (RFC 5952), hence Rust.
pub async fn canonicalize_stored_subnets(pool: &SqlitePool) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let rows: Vec<(i64, String, i64)> =
        sqlx::query_as("SELECT id, subnet_cidr, group_id FROM client_subnets ORDER BY id")
            .fetch_all(&mut *tx)
            .await?;

    // Canonical text -> (id, group_id) of the row that keeps it.
    let mut kept: HashMap<String, (i64, i64)> = HashMap::with_capacity(rows.len());
    let mut duplicates = Vec::new();
    let mut rewrites = Vec::new();
    for (id, stored, group_id) in rows {
        let canonical = match ClientSubnet::parse_cidr(&stored) {
            Ok(network) => network.to_string(),
            Err(e) => {
                warn!(id, subnet = %stored, error = %e, "Leaving unparseable client subnet as stored");
                kept.entry(stored).or_insert((id, group_id));
                continue;
            }
        };
        if let Some(&(kept_id, kept_group_id)) = kept.get(&canonical) {
            if kept_group_id == group_id {
                warn!(
                    dropped_id = id, dropped_subnet = %stored, dropped_group_id = group_id,
                    kept_id, kept_group_id, canonical = %canonical,
                    "Dropping duplicate client subnet"
                );
            } else {
                warn!(
                    dropped_id = id, dropped_subnet = %stored, dropped_group_id = group_id,
                    kept_id, kept_group_id, canonical = %canonical,
                    "Dropping duplicate client subnet from another group; clients in {canonical} now belong to group {kept_group_id}"
                );
            }
            duplicates.push(id);
        } else {
            if canonical != stored {
                rewrites.push((id, canonical.clone()));
            }
            kept.insert(canonical, (id, group_id));
        }
    }

    // Deletes first: a survivor's canonical text may equal a duplicate's stored text.
    for id in &duplicates {
        sqlx::query("DELETE FROM client_subnets WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    for (id, canonical) in &rewrites {
        sqlx::query("UPDATE client_subnets SET subnet_cidr = ? WHERE id = ?")
            .bind(canonical)
            .bind(id)
            .execute(&mut *tx)
            .await?;
    }
    let changed = (duplicates.len() + rewrites.len()) as u64;

    tx.commit().await?;
    Ok(changed)
}
