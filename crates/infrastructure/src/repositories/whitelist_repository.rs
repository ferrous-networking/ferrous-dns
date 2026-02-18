use async_trait::async_trait;
use dashmap::DashSet;
use ferrous_dns_application::ports::WhitelistRepository;
use ferrous_dns_domain::{whitelist::WhitelistedDomain, DomainError};
use rustc_hash::FxBuildHasher;
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use tracing::{debug, info};

pub struct SqliteWhitelistRepository {
    pool: SqlitePool,
    whitelisted_domains: Arc<DashSet<String, FxBuildHasher>>,
}

impl SqliteWhitelistRepository {
    pub async fn load(pool: SqlitePool) -> Result<Self, DomainError> {
        let whitelisted_domains = DashSet::with_hasher(FxBuildHasher);
        let rows = sqlx::query("SELECT domain FROM whitelist")
            .fetch_all(&pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;
        for row in &rows {
            whitelisted_domains.insert(row.get("domain"));
        }
        info!(domains_loaded = rows.len(), "Whitelist loaded into memory");
        Ok(Self {
            pool,
            whitelisted_domains: Arc::new(whitelisted_domains),
        })
    }

    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            whitelisted_domains: Arc::new(DashSet::with_hasher(FxBuildHasher)),
        }
    }
}

#[async_trait]
impl WhitelistRepository for SqliteWhitelistRepository {
    async fn get_all(&self) -> Result<Vec<WhitelistedDomain>, DomainError> {
        let rows = sqlx::query("SELECT id, domain, datetime(added_at) as added_at FROM whitelist ORDER BY added_at DESC")
            .fetch_all(&self.pool).await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;
        Ok(rows
            .into_iter()
            .map(|row| WhitelistedDomain {
                id: Some(row.get("id")),
                domain: row.get("domain"),
                added_at: Some(row.get("added_at")),
            })
            .collect())
    }

    async fn add_domain(&self, domain: &WhitelistedDomain) -> Result<(), DomainError> {
        sqlx::query("INSERT INTO whitelist (domain) VALUES (?)")
            .bind(&domain.domain)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;
        self.whitelisted_domains.insert(domain.domain.clone());
        debug!(domain = %domain.domain, "Domain added to whitelist");
        Ok(())
    }

    async fn remove_domain(&self, domain: &str) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM whitelist WHERE domain = ?")
            .bind(domain)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;
        self.whitelisted_domains.remove(domain);
        debug!(domain = %domain, "Domain removed from whitelist");
        Ok(())
    }

    async fn is_whitelisted(&self, domain: &str) -> Result<bool, DomainError> {
        Ok(self.whitelisted_domains.contains(domain))
    }
}
