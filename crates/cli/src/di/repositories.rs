use ferrous_dns_infrastructure::repositories::{
    blocklist_repository::SqliteBlocklistRepository,
    blocklist_source_repository::SqliteBlocklistSourceRepository,
    client_repository::SqliteClientRepository,
    client_subnet_repository::SqliteClientSubnetRepository,
    config_repository::SqliteConfigRepository, group_repository::SqliteGroupRepository,
    query_log_repository::SqliteQueryLogRepository,
};
use sqlx::SqlitePool;
use std::sync::Arc;

pub struct Repositories {
    pub query_log: Arc<SqliteQueryLogRepository>,
    pub blocklist: Arc<SqliteBlocklistRepository>,
    pub blocklist_source: Arc<SqliteBlocklistSourceRepository>,
    pub config: Arc<SqliteConfigRepository>,
    pub client: Arc<SqliteClientRepository>,
    pub group: Arc<SqliteGroupRepository>,
    pub client_subnet: Arc<SqliteClientSubnetRepository>,
}

impl Repositories {
    pub async fn new(pool: SqlitePool) -> Result<Self, ferrous_dns_domain::DomainError> {
        let blocklist = SqliteBlocklistRepository::load(pool.clone()).await?;
        Ok(Self {
            query_log: Arc::new(SqliteQueryLogRepository::new(pool.clone())),
            blocklist: Arc::new(blocklist),
            blocklist_source: Arc::new(SqliteBlocklistSourceRepository::new(pool.clone())),
            config: Arc::new(SqliteConfigRepository::new(pool.clone())),
            client: Arc::new(SqliteClientRepository::new(pool.clone())),
            group: Arc::new(SqliteGroupRepository::new(pool.clone())),
            client_subnet: Arc::new(SqliteClientSubnetRepository::new(pool)),
        })
    }
}
