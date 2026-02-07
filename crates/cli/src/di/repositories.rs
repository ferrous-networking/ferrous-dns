use ferrous_dns_infrastructure::repositories::{
    blocklist_repository::SqliteBlocklistRepository, config_repository::SqliteConfigRepository,
    query_log_repository::SqliteQueryLogRepository,
};
use sqlx::SqlitePool;
use std::sync::Arc;

pub struct Repositories {
    pub query_log: Arc<SqliteQueryLogRepository>,
    pub blocklist: Arc<SqliteBlocklistRepository>,
    pub config: Arc<SqliteConfigRepository>,
}

impl Repositories {
    pub async fn new(pool: SqlitePool) -> Result<Self, ferrous_dns_domain::DomainError> {
        let blocklist = SqliteBlocklistRepository::load(pool.clone()).await?;
        Ok(Self {
            query_log: Arc::new(SqliteQueryLogRepository::new(pool.clone())),
            blocklist: Arc::new(blocklist),
            config: Arc::new(SqliteConfigRepository::new(pool)),
        })
    }
}
