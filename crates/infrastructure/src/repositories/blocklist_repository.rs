//! Blocklist repository with in-memory DashSet backed by SQLite.
//! is_blocked() hot path: DashSet lookup ~20ns vs SQLite SELECT ~200µs

use async_trait::async_trait;
use dashmap::DashSet;
use ferrous_dns_application::ports::BlocklistRepository;
use ferrous_dns_domain::{blocklist::BlockedDomain, DomainError};
use rustc_hash::FxBuildHasher;
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use tracing::{debug, info};

pub struct SqliteBlocklistRepository {
    pool: SqlitePool,
    blocked_domains: Arc<DashSet<String, FxBuildHasher>>,
}

impl SqliteBlocklistRepository {
    pub async fn load(pool: SqlitePool) -> Result<Self, DomainError> {
        let blocked_domains = DashSet::with_hasher(FxBuildHasher::default());
        let rows = sqlx::query("SELECT domain FROM blocklist")
            .fetch_all(&pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;
        for row in &rows {
            blocked_domains.insert(row.get("domain"));
        }
        info!(domains_loaded = rows.len(), "Blocklist loaded into memory");
        Ok(Self {
            pool,
            blocked_domains: Arc::new(blocked_domains),
        })
    }

    pub fn new(pool: SqlitePool) -> Self {
        Self {
            pool,
            blocked_domains: Arc::new(DashSet::with_hasher(FxBuildHasher::default())),
        }
    }
}

#[async_trait]
impl BlocklistRepository for SqliteBlocklistRepository {
    async fn get_all(&self) -> Result<Vec<BlockedDomain>, DomainError> {
        let rows = sqlx::query("SELECT id, domain, datetime(added_at) as added_at FROM blocklist ORDER BY added_at DESC")
            .fetch_all(&self.pool).await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;
        Ok(rows
            .into_iter()
            .map(|row| BlockedDomain {
                id: Some(row.get("id")),
                domain: row.get("domain"),
                added_at: Some(row.get("added_at")),
            })
            .collect())
    }

    async fn add_domain(&self, domain: &BlockedDomain) -> Result<(), DomainError> {
        sqlx::query("INSERT INTO blocklist (domain) VALUES (?)")
            .bind(&domain.domain)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;
        self.blocked_domains.insert(domain.domain.clone());
        debug!(domain = %domain.domain, "Domain added to blocklist");
        Ok(())
    }

    async fn remove_domain(&self, domain: &str) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM blocklist WHERE domain = ?")
            .bind(domain)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;
        self.blocked_domains.remove(domain);
        debug!(domain = %domain, "Domain removed from blocklist");
        Ok(())
    }

    async fn is_blocked(&self, domain: &str) -> Result<bool, DomainError> {
        Ok(self.blocked_domains.contains(domain))
    }
}
