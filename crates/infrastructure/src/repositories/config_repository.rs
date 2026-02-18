use async_trait::async_trait;
use ferrous_dns_application::ports::ConfigRepository;
use ferrous_dns_domain::{Config, DomainError};
use sqlx::{Row, SqlitePool};

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
    async fn get_config(&self) -> Result<Config, DomainError> {
        let row = sqlx::query(
            "SELECT upstream_dns, cache_enabled, cache_ttl_seconds, blocklist_enabled
             FROM config
             WHERE id = 1",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;

        match row {
            Some(row) => {
                let upstream_dns_str: String = row.get("upstream_dns");
                let upstream_servers: Vec<String> = upstream_dns_str
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();

                let mut config = Config::default();

                config.dns.upstream_servers = upstream_servers;
                config.dns.cache_enabled = row.get::<i64, _>("cache_enabled") != 0;
                config.dns.cache_ttl = row.get::<i64, _>("cache_ttl_seconds") as u32;

                config.blocking.enabled = row.get::<i64, _>("blocklist_enabled") != 0;

                Ok(config)
            }
            None => {
                let default = Config::default();
                self.save_config(&default).await?;
                Ok(default)
            }
        }
    }

    async fn save_config(&self, config: &Config) -> Result<(), DomainError> {
        let upstream_dns = config.dns.upstream_servers.join(",");

        let cache_enabled = if config.dns.cache_enabled { 1 } else { 0 };
        let blocklist_enabled = if config.blocking.enabled { 1 } else { 0 };

        sqlx::query(
            "INSERT INTO config (id, upstream_dns, cache_enabled, cache_ttl_seconds, blocklist_enabled)
             VALUES (1, ?, ?, ?, ?)
             ON CONFLICT(id) DO UPDATE SET
                upstream_dns = excluded.upstream_dns,
                cache_enabled = excluded.cache_enabled,
                cache_ttl_seconds = excluded.cache_ttl_seconds,
                blocklist_enabled = excluded.blocklist_enabled"
        )
            .bind(&upstream_dns)
            .bind(cache_enabled)
            .bind(config.dns.cache_ttl as i64)
            .bind(blocklist_enabled)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;

        Ok(())
    }
}
