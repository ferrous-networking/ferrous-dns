use ferrous_dns_application::ports::BlockFilterEnginePort;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::repositories::{
    blocklist_repository::SqliteBlocklistRepository,
    blocklist_source_repository::SqliteBlocklistSourceRepository,
    client_repository::SqliteClientRepository,
    client_subnet_repository::SqliteClientSubnetRepository,
    config_repository::SqliteConfigRepository, group_repository::SqliteGroupRepository,
    managed_domain_repository::SqliteManagedDomainRepository,
    query_log_repository::SqliteQueryLogRepository,
    whitelist_repository::SqliteWhitelistRepository,
    whitelist_source_repository::SqliteWhitelistSourceRepository,
};
use sqlx::{Row, SqlitePool};
use std::sync::Arc;

pub struct Repositories {
    pub query_log: Arc<SqliteQueryLogRepository>,
    pub blocklist: Arc<SqliteBlocklistRepository>,
    pub blocklist_source: Arc<SqliteBlocklistSourceRepository>,
    pub whitelist: Arc<SqliteWhitelistRepository>,
    pub whitelist_source: Arc<SqliteWhitelistSourceRepository>,
    pub config: Arc<SqliteConfigRepository>,
    pub client: Arc<SqliteClientRepository>,
    pub group: Arc<SqliteGroupRepository>,
    pub client_subnet: Arc<SqliteClientSubnetRepository>,
    pub managed_domain: Arc<SqliteManagedDomainRepository>,
    pub block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl Repositories {
    pub async fn new(pool: SqlitePool) -> Result<Self, ferrous_dns_domain::DomainError> {
        let blocklist = SqliteBlocklistRepository::load(pool.clone()).await?;
        let whitelist = SqliteWhitelistRepository::load(pool.clone()).await?;

        // Determine the default group id for the BlockFilterEngine
        let default_group_id: i64 =
            sqlx::query("SELECT id FROM groups WHERE is_default = 1 LIMIT 1")
                .fetch_optional(&pool)
                .await
                .map_err(|e| ferrous_dns_domain::DomainError::DatabaseError(e.to_string()))?
                .map(|row| row.get::<i64, _>("id"))
                .unwrap_or(1);

        let block_filter_engine: Arc<dyn BlockFilterEnginePort> =
            Arc::new(BlockFilterEngine::new(pool.clone(), default_group_id).await?);

        Ok(Self {
            query_log: Arc::new(SqliteQueryLogRepository::new(pool.clone())),
            blocklist: Arc::new(blocklist),
            blocklist_source: Arc::new(SqliteBlocklistSourceRepository::new(pool.clone())),
            whitelist: Arc::new(whitelist),
            whitelist_source: Arc::new(SqliteWhitelistSourceRepository::new(pool.clone())),
            config: Arc::new(SqliteConfigRepository::new(pool.clone())),
            client: Arc::new(SqliteClientRepository::new(pool.clone())),
            group: Arc::new(SqliteGroupRepository::new(pool.clone())),
            client_subnet: Arc::new(SqliteClientSubnetRepository::new(pool.clone())),
            managed_domain: Arc::new(SqliteManagedDomainRepository::new(pool)),
            block_filter_engine,
        })
    }
}
