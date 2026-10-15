use super::client_row_mapper::{
    row_to_client, ClientRow, CLIENT_SELECT_ACTIVE, CLIENT_SELECT_ALL, CLIENT_SELECT_BY_ID,
    CLIENT_SELECT_BY_IP, CLIENT_SELECT_NEEDS_HOSTNAME_UPDATE, CLIENT_SELECT_NEEDS_MAC_UPDATE,
};
use crate::repositories::{db_err, hours_ago_cutoff, is_fk_violation, sql_now};
use async_trait::async_trait;
use ferrous_dns_application::ports::ClientRepository;
use ferrous_dns_domain::{config::DatabaseConfig, Client, ClientStats, DomainError};
use sqlx::SqlitePool;
use std::net::IpAddr;
use tokio::sync::{mpsc, oneshot};
use tracing::{instrument, warn};

const UPDATE_MAC_SQL: &str = "UPDATE clients SET
                 mac_address = ?,
                 last_mac_update = ?,
                 updated_at = ?
             WHERE ip_address = ?";

enum ClientMsg {
    IpSeen(IpAddr),
    Flush(oneshot::Sender<()>),
}

pub struct SqliteClientRepository {
    pool: SqlitePool,
    sender: mpsc::Sender<ClientMsg>,
}

impl SqliteClientRepository {
    pub fn new(pool: SqlitePool, cfg: &DatabaseConfig) -> Self {
        let (sender, receiver) = mpsc::channel(cfg.client_channel_capacity);
        let write_pool = pool.clone();
        tokio::spawn(async move {
            Self::track_loop(write_pool, receiver).await;
        });
        Self { pool, sender }
    }

    async fn track_loop(pool: SqlitePool, mut receiver: mpsc::Receiver<ClientMsg>) {
        while let Some(msg) = receiver.recv().await {
            match msg {
                ClientMsg::IpSeen(ip) => {
                    let timestamp = sql_now();

                    if let Err(e) = sqlx::query(
                        "INSERT INTO clients (ip_address, first_seen, last_seen, query_count)
                         VALUES (?, ?, ?, 1)
                         ON CONFLICT(ip_address) DO UPDATE SET
                             last_seen = excluded.last_seen,
                             query_count = query_count + 1,
                             updated_at = excluded.last_seen",
                    )
                    .bind(ip.to_string())
                    .bind(&timestamp)
                    .bind(&timestamp)
                    .execute(&pool)
                    .await
                    {
                        warn!(error = %e, %ip, "Failed to update client last_seen");
                    }
                }
                ClientMsg::Flush(ack) => {
                    let _ = ack.send(());
                }
            }
        }
    }

    pub async fn flush_writes(&self) {
        let (tx, rx) = oneshot::channel();
        if self.sender.send(ClientMsg::Flush(tx)).await.is_ok() {
            let _ = rx.await;
        }
    }
}

#[async_trait]
impl ClientRepository for SqliteClientRepository {
    #[instrument(skip(self))]
    async fn get_or_create(&self, ip_address: IpAddr) -> Result<Client, DomainError> {
        let ip_str = ip_address.to_string();
        let now = sql_now();

        sqlx::query(
            "INSERT INTO clients (ip_address, first_seen, last_seen, query_count)
             VALUES (?, ?, ?, 0)
             ON CONFLICT(ip_address) DO NOTHING",
        )
        .bind(&ip_str)
        .bind(&now)
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(db_err("Failed to upsert client"))?;

        let row: ClientRow = sqlx::query_as::<_, ClientRow>(CLIENT_SELECT_BY_IP)
            .bind(&ip_str)
            .fetch_one(&self.pool)
            .await
            .map_err(db_err("Failed to fetch client after upsert"))?;

        row_to_client(row)
            .ok_or_else(|| DomainError::DatabaseError("Invalid client data".to_string()))
    }

    async fn update_last_seen(&self, ip_address: IpAddr) -> Result<(), DomainError> {
        let _ = self.sender.try_send(ClientMsg::IpSeen(ip_address));
        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_mac_address(&self, ip_address: IpAddr, mac: String) -> Result<(), DomainError> {
        let now = sql_now();

        sqlx::query(UPDATE_MAC_SQL)
            .bind(&mac)
            .bind(&now)
            .bind(&now)
            .bind(ip_address.to_string())
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to update MAC address"))?;

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

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(db_err("Failed to begin transaction"))?;

        let mut updated_count = 0u64;
        let now = sql_now();

        for (ip_address, mac) in updates {
            let result = sqlx::query(UPDATE_MAC_SQL)
                .bind(&mac)
                .bind(&now)
                .bind(&now)
                .bind(ip_address.to_string())
                .execute(&mut *tx)
                .await
                .map_err(db_err("Failed to update MAC in batch"))?;

            updated_count += result.rows_affected();
        }

        tx.commit()
            .await
            .map_err(db_err("Failed to commit batch MAC update"))?;

        Ok(updated_count)
    }

    #[instrument(skip(self))]
    async fn update_hostname(
        &self,
        ip_address: IpAddr,
        hostname: String,
    ) -> Result<(), DomainError> {
        let now = sql_now();

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
        .bind(ip_address.to_string())
        .execute(&self.pool)
        .await
        .map_err(db_err("Failed to update hostname"))?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_all(&self, limit: u32, offset: u32) -> Result<Vec<Client>, DomainError> {
        let rows = sqlx::query_as::<_, ClientRow>(CLIENT_SELECT_ALL)
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await
            .map_err(db_err("Failed to fetch clients"))?;

        Ok(rows.into_iter().filter_map(row_to_client).collect())
    }

    #[instrument(skip(self))]
    async fn get_active(&self, days: u32, limit: u32) -> Result<Vec<Client>, DomainError> {
        let rows = sqlx::query_as::<_, ClientRow>(CLIENT_SELECT_ACTIVE)
            .bind(format!("-{days} days"))
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(db_err("Failed to fetch active clients"))?;

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
        .map_err(db_err("Failed to fetch client stats"))?;

        Ok(ClientStats {
            total_clients: row.0 as u64,
            active_24h: row.1 as u64,
            active_7d: row.2 as u64,
            with_mac: row.3 as u64,
            with_hostname: row.4 as u64,
        })
    }

    #[instrument(skip(self))]
    async fn count_active_since(&self, hours: f32) -> Result<u64, DomainError> {
        let row = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM clients WHERE last_seen >= ?")
            .bind(hours_ago_cutoff(hours))
            .fetch_one(&self.pool)
            .await
            .map_err(db_err("Failed to count active clients"))?;

        Ok(row.0 as u64)
    }

    #[instrument(skip(self))]
    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError> {
        let result = sqlx::query("DELETE FROM clients WHERE last_seen < datetime('now', ?)")
            .bind(format!("-{days} days"))
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to delete old clients"))?;

        Ok(result.rows_affected())
    }

    #[instrument(skip(self))]
    async fn get_needs_mac_update(&self, limit: u32) -> Result<Vec<Client>, DomainError> {
        let rows = sqlx::query_as::<_, ClientRow>(CLIENT_SELECT_NEEDS_MAC_UPDATE)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(db_err("Failed to fetch clients needing MAC update"))?;

        Ok(rows.into_iter().filter_map(row_to_client).collect())
    }

    #[instrument(skip(self))]
    async fn get_needs_hostname_update(&self, limit: u32) -> Result<Vec<Client>, DomainError> {
        let rows = sqlx::query_as::<_, ClientRow>(CLIENT_SELECT_NEEDS_HOSTNAME_UPDATE)
            .bind(i64::from(limit))
            .fetch_all(&self.pool)
            .await
            .map_err(db_err("Failed to fetch clients needing hostname update"))?;

        Ok(rows.into_iter().filter_map(row_to_client).collect())
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<Client>, DomainError> {
        let row = sqlx::query_as::<_, ClientRow>(CLIENT_SELECT_BY_ID)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err("Failed to fetch client by id"))?;

        Ok(row.and_then(row_to_client))
    }

    #[instrument(skip(self))]
    async fn get_by_ip(&self, ip_address: IpAddr) -> Result<Option<Client>, DomainError> {
        let row = sqlx::query_as::<_, ClientRow>(CLIENT_SELECT_BY_IP)
            .bind(ip_address.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(db_err("Failed to fetch client by ip"))?;

        Ok(row.and_then(row_to_client))
    }

    #[instrument(skip(self))]
    async fn assign_group(&self, client_id: i64, group_id: i64) -> Result<(), DomainError> {
        let result = sqlx::query(
            "UPDATE clients SET group_id = ?, updated_at = ?
             WHERE id = ?",
        )
        .bind(group_id)
        .bind(sql_now())
        .bind(client_id)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            if is_fk_violation(&e) {
                DomainError::GroupNotFound(group_id)
            } else {
                db_err("Failed to assign client to group")(e)
            }
        })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound(format!(
                "Client {client_id} not found"
            )));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn set_comment(&self, id: i64, comment: Option<String>) -> Result<(), DomainError> {
        let result = sqlx::query("UPDATE clients SET comment = ?, updated_at = ? WHERE id = ?")
            .bind(&comment)
            .bind(sql_now())
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(db_err("Failed to set client comment"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::ClientNotFound(format!(
                "Client {id} not found"
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
            .map_err(db_err("Failed to delete client"))?;

        if result.rows_affected() == 0 {
            return Err(DomainError::NotFound(format!("Client {id} not found")));
        }

        Ok(())
    }
}
