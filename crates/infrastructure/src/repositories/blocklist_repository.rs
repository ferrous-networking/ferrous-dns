use async_trait::async_trait;
use ferrous_dns_application::ports::BlocklistRepository;
use ferrous_dns_domain::{blocklist::BlockedDomain, DomainError};
use sqlx::{Row, SqlitePool};

pub struct SqliteBlocklistRepository {
    pool: SqlitePool,
}

impl SqliteBlocklistRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl BlocklistRepository for SqliteBlocklistRepository {
    async fn get_all(&self) -> Result<Vec<BlockedDomain>, DomainError> {
        let rows = sqlx::query(
            "SELECT id, domain, datetime(added_at) as added_at
             FROM blocklist
             ORDER BY added_at DESC"
        )
            .fetch_all(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;

        let entries = rows
            .into_iter()
            .map(|row| BlockedDomain {
                id: Some(row.get("id")),
                domain: row.get("domain"),
                added_at: Some(row.get("added_at")),
            })
            .collect();

        Ok(entries)
    }

    async fn add_domain(&self, domain: &BlockedDomain) -> Result<(), DomainError> {
        sqlx::query("INSERT INTO blocklist (domain) VALUES (?)")
            .bind(&domain.domain)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;

        Ok(())
    }

    async fn remove_domain(&self, domain: &str) -> Result<(), DomainError> {
        sqlx::query("DELETE FROM blocklist WHERE domain = ?")
            .bind(domain)
            .execute(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;

        Ok(())
    }

    async fn is_blocked(&self, domain: &str) -> Result<bool, DomainError> {
        let row = sqlx::query("SELECT COUNT(*) as count FROM blocklist WHERE domain = ?")
            .bind(domain)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Database error: {}", e)))?;

        Ok(row.get::<i64, _>("count") > 0)
    }
}
