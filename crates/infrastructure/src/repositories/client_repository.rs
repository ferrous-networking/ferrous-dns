use super::client_row_mapper::{row_to_client, ClientRow, CLIENT_SELECT};
use async_trait::async_trait;
use ferrous_dns_application::ports::ClientRepository;
use ferrous_dns_domain::{Client, ClientStats, DomainError};
use sqlx::SqlitePool;
use std::net::IpAddr;
use tracing::{error, instrument};

pub struct SqliteClientRepository {
    pool: SqlitePool,
}

impl SqliteClientRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ClientRepository for SqliteClientRepository {
    #[instrument(skip(self))]
    async fn get_or_create(&self, ip_address: IpAddr) -> Result<Client, DomainError> {
        let ip_str = ip_address.to_string();

        let existing: Option<ClientRow> =
            sqlx::query_as::<_, ClientRow>(&format!("{} WHERE ip_address = ?", CLIENT_SELECT))
                .bind(&ip_str)
                .fetch_optional(&self.pool)
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to query client");
                    DomainError::DatabaseError(e.to_string())
                })?;

        if let Some(row) = existing {
            let client = row_to_client(row)
                .ok_or_else(|| DomainError::DatabaseError("Invalid client data".to_string()))?;
            Ok(client)
        } else {
            let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

            sqlx::query(
                "INSERT INTO clients (ip_address, first_seen, last_seen, query_count)
                 VALUES (?, ?, ?, 0)",
            )
            .bind(&ip_str)
            .bind(&now)
            .bind(&now)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to create client");
                DomainError::DatabaseError(e.to_string())
            })?;

            Ok(Client::new(ip_address))
        }
    }

    #[instrument(skip(self))]
    async fn update_last_seen(&self, ip_address: IpAddr) -> Result<(), DomainError> {
        let ip_str = ip_address.to_string();
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        sqlx::query(
            "INSERT INTO clients (ip_address, first_seen, last_seen, query_count)
             VALUES (?, ?, ?, 1)
             ON CONFLICT(ip_address) DO UPDATE SET
                 last_seen = ?,
                 query_count = query_count + 1,
                 updated_at = ?",
        )
        .bind(&ip_str)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, ip = %ip_address, "Failed to update last_seen");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_mac_address(&self, ip_address: IpAddr, mac: String) -> Result<(), DomainError> {
        let ip_str = ip_address.to_string();
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        sqlx::query(
            "UPDATE clients SET
                 mac_address = ?,
                 last_mac_update = ?,
                 updated_at = ?
             WHERE ip_address = ?",
        )
        .bind(&mac)
        .bind(&now)
        .bind(&now)
        .bind(&ip_str)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to update MAC address");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(())
    }

    #[instrument(skip(self, updates))]
    async fn batch_update_mac_addresses(
        &self,
        updates: Vec<(IpAddr, String)>,
    ) -> Result<u64, DomainError> {
        if updates.is_empty() {
            return Ok(0);
        }

        let mut tx = self.pool.begin().await.map_err(|e| {
            error!(error = %e, "Failed to begin transaction");
            DomainError::DatabaseError(e.to_string())
        })?;

        let mut updated_count = 0u64;
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        for (ip_address, mac) in updates {
            let ip_str = ip_address.to_string();

            let result = sqlx::query(
                "UPDATE clients SET
                     mac_address = ?,
                     last_mac_update = ?,
                     updated_at = ?
                 WHERE ip_address = ?",
            )
            .bind(&mac)
            .bind(&now)
            .bind(&now)
            .bind(&ip_str)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!(error = %e, ip = %ip_address, "Failed to update MAC in batch");
                DomainError::DatabaseError(e.to_string())
            })?;

            updated_count += result.rows_affected();
        }

        tx.commit().await.map_err(|e| {
            error!(error = %e, "Failed to commit batch MAC update");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(updated_count)
    }

    #[instrument(skip(self))]
    async fn update_hostname(
        &self,
        ip_address: IpAddr,
        hostname: String,
    ) -> Result<(), DomainError> {
        let ip_str = ip_address.to_string();
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        sqlx::query(
            "UPDATE clients SET
                 hostname = ?,
                 last_hostname_update = ?,
                 updated_at = ?
             WHERE ip_address = ?",
        )
        .bind(&hostname)
        .bind(&now)
        .bind(&now)
        .bind(&ip_str)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to update hostname");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_all(&self, limit: u32, offset: u32) -> Result<Vec<Client>, DomainError> {
        let rows = sqlx::query_as::<_, ClientRow>(&format!(
            "{} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            CLIENT_SELECT
        ))
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch clients");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().filter_map(row_to_client).collect())
    }

    #[instrument(skip(self))]
    async fn get_active(&self, days: u32, limit: u32) -> Result<Vec<Client>, DomainError> {
        let rows = sqlx::query_as::<_, ClientRow>(&format!(
            "{} WHERE last_seen > datetime('now', ?) ORDER BY last_seen DESC LIMIT ?",
            CLIENT_SELECT
        ))
        .bind(format!("-{} days", days))
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch active clients");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().filter_map(row_to_client).collect())
    }

    #[instrument(skip(self))]
    async fn get_stats(&self) -> Result<ClientStats, DomainError> {
        let row = sqlx::query_as::<_, (i64, i64, i64, i64, i64)>(
            "SELECT
                COUNT(*) as total,
                COUNT(CASE WHEN last_seen > datetime('now', '-1 day') THEN 1 END) as active_24h,
                COUNT(CASE WHEN last_seen > datetime('now', '-7 days') THEN 1 END) as active_7d,
                COUNT(CASE WHEN mac_address IS NOT NULL THEN 1 END) as with_mac,
                COUNT(CASE WHEN hostname IS NOT NULL THEN 1 END) as with_hostname
             FROM clients",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch client stats");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(ClientStats {
            total_clients: row.0 as u64,
            active_24h: row.1 as u64,
            active_7d: row.2 as u64,
            with_mac: row.3 as u64,
            with_hostname: row.4 as u64,
        })
    }

    #[instrument(skip(self))]
    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError> {
        let result = sqlx::query("DELETE FROM clients WHERE last_seen < datetime('now', ?)")
            .bind(format!("-{} days", days))
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete old clients");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(result.rows_affected())
    }

    #[instrument(skip(self))]
    async fn get_needs_mac_update(&self, limit: u32) -> Result<Vec<Client>, DomainError> {
        let rows = sqlx::query_as::<_, ClientRow>(&format!(
            "{} WHERE (last_mac_update IS NULL
                       OR last_mac_update < datetime('now', '-5 minutes'))
             AND last_seen > datetime('now', '-1 day')
             ORDER BY last_seen DESC LIMIT ?",
            CLIENT_SELECT
        ))
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch clients needing MAC update");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().filter_map(row_to_client).collect())
    }

    #[instrument(skip(self))]
    async fn get_needs_hostname_update(&self, limit: u32) -> Result<Vec<Client>, DomainError> {
        let rows = sqlx::query_as::<_, ClientRow>(&format!(
            "{} WHERE (last_hostname_update IS NULL
                       OR last_hostname_update < datetime('now', '-1 hour'))
             AND last_seen > datetime('now', '-7 days')
             ORDER BY last_seen DESC LIMIT ?",
            CLIENT_SELECT
        ))
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch clients needing hostname update");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().filter_map(row_to_client).collect())
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<Client>, DomainError> {
        let row = sqlx::query_as::<_, ClientRow>(&format!("{} WHERE id = ?", CLIENT_SELECT))
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to fetch client by id");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(row.and_then(row_to_client))
    }

    #[instrument(skip(self))]
    async fn assign_group(&self, client_id: i64, group_id: i64) -> Result<(), DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let result = sqlx::query(
            "UPDATE clients SET group_id = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(group_id)
        .bind(&now)
        .bind(client_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to assign client to group");
            DomainError::DatabaseError(e.to_string())
        })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound(format!(
                "Client {} not found",
                client_id
            )));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM clients WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to delete client");
                DomainError::DatabaseError(e.to_string())
            })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound(format!("Client {} not found", id)));
        }

        Ok(())
    }
}
