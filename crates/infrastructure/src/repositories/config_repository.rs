use async_trait::async_trait;
use ferrous_dns_application::ports::ConfigRepository;
use ferrous_dns_domain::{DnsConfig, DomainError};
use sqlx::{Row, SqlitePool};
use std::net::IpAddr;

pub struct SqliteConfigRepository {
    pool: SqlitePool,
}

impl SqliteConfigRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ConfigRepository for SqliteConfigRepository {
    async fn get_config(&self) -> Result<DnsConfig, DomainError> {
        let row = sqlx::query(
            "SELECT id, upstream_dns, cache_enabled, cache_ttl_seconds, blocklist_enabled
             FROM config
             WHERE id = 1"
        )
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;

        match row {
            Some(row) => {
                let upstream_dns_str: String = row.get("upstream_dns");
                let upstream_dns: Vec<IpAddr> = upstream_dns_str
                    .split(',')
                    .filter_map(|s| s.trim().parse().ok())
                    .collect();

                Ok(DnsConfig {
                    id: row.get("id"),
                    upstream_dns,
                    cache_enabled: row.get::<i64, _>("cache_enabled") != 0,
                    cache_ttl_seconds: row.get("cache_ttl_seconds"),
                    blocklist_enabled: row.get::<i64, _>("blocklist_enabled") != 0,
                })
            }
            None => {
                // Insert default config
                let default = DnsConfig::default();
                self.save_config(&default).await?;
                Ok(default)
            }
        }
    }

    async fn save_config(&self, config: &DnsConfig) -> Result<(), DomainError> {
        let upstream_dns = config.upstream_dns
            .iter()
            .map(|ip| ip.to_string())
            .collect::<Vec<_>>()
            .join(",");

        let cache_enabled = if config.cache_enabled { 1 } else { 0 };
        let blocklist_enabled = if config.blocklist_enabled { 1 } else { 0 };

        sqlx::query(
            "INSERT INTO config (id, upstream_dns, cache_enabled, cache_ttl_seconds, blocklist_enabled)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                upstream_dns = excluded.upstream_dns,
                cache_enabled = excluded.cache_enabled,
                cache_ttl_seconds = excluded.cache_ttl_seconds,
                blocklist_enabled = excluded.blocklist_enabled"
        )
            .bind(config.id)
            .bind(&upstream_dns)
            .bind(cache_enabled)
            .bind(config.cache_ttl_seconds)
            .bind(blocklist_enabled)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;

        Ok(())
    }
}
