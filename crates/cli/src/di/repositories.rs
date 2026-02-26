use ferrous_dns_application::ports::{
    BlockFilterEnginePort, CustomServiceRepository, ServiceCatalogPort,
};
use ferrous_dns_application::use_cases::custom_services::custom_to_definition;
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::dns::BlockFilterEngine;
use ferrous_dns_infrastructure::repositories::{
    blocked_service_repository::SqliteBlockedServiceRepository,
    blocklist_repository::SqliteBlocklistRepository,
    blocklist_source_repository::SqliteBlocklistSourceRepository,
    client_repository::SqliteClientRepository,
    client_subnet_repository::SqliteClientSubnetRepository,
    custom_service_repository::SqliteCustomServiceRepository,
    group_repository::SqliteGroupRepository,
    managed_domain_repository::SqliteManagedDomainRepository,
    query_log_repository::SqliteQueryLogRepository,
    regex_filter_repository::SqliteRegexFilterRepository,
    whitelist_repository::SqliteWhitelistRepository,
    whitelist_source_repository::SqliteWhitelistSourceRepository,
};
use ferrous_dns_infrastructure::service_catalog::{CompositeServiceCatalog, ServiceCatalog};
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use tracing::info;

pub struct Repositories {
    pub query_log: Arc<SqliteQueryLogRepository>,
    pub blocklist: Arc<SqliteBlocklistRepository>,
    pub blocklist_source: Arc<SqliteBlocklistSourceRepository>,
    pub whitelist: Arc<SqliteWhitelistRepository>,
    pub whitelist_source: Arc<SqliteWhitelistSourceRepository>,
    pub client: Arc<SqliteClientRepository>,
    pub group: Arc<SqliteGroupRepository>,
    pub client_subnet: Arc<SqliteClientSubnetRepository>,
    pub managed_domain: Arc<SqliteManagedDomainRepository>,
    pub regex_filter: Arc<SqliteRegexFilterRepository>,
    pub blocked_service: Arc<SqliteBlockedServiceRepository>,
    pub custom_service: Arc<SqliteCustomServiceRepository>,
    pub service_catalog: Arc<dyn ServiceCatalogPort>,
    pub block_filter_engine: Arc<dyn BlockFilterEnginePort>,
}

impl Repositories {
    pub async fn new(
        write_pool: SqlitePool,
        read_pool: SqlitePool,
        db_config: &DatabaseConfig,
    ) -> Result<Self, ferrous_dns_domain::DomainError> {
        let blocklist = SqliteBlocklistRepository::load(write_pool.clone()).await?;
        let whitelist = SqliteWhitelistRepository::load(write_pool.clone()).await?;

        let default_group_id: i64 =
            sqlx::query("SELECT id FROM groups WHERE is_default = 1 LIMIT 1")
                .fetch_optional(&write_pool)
                .await
                .map_err(|e| ferrous_dns_domain::DomainError::DatabaseError(e.to_string()))?
                .map(|row| row.get::<i64, _>("id"))
                .unwrap_or(1);

        let block_filter_engine: Arc<dyn BlockFilterEnginePort> =
            BlockFilterEngine::new(write_pool.clone(), default_group_id).await?;

        let composite = CompositeServiceCatalog::new(ServiceCatalog::load());
        let service_catalog: Arc<dyn ServiceCatalogPort> = Arc::new(composite);

        let custom_service = Arc::new(SqliteCustomServiceRepository::new(write_pool.clone()));

        if let Ok(customs) = custom_service.get_all().await {
            let defs: Vec<_> = customs.iter().map(custom_to_definition).collect();
            let count = defs.len();
            service_catalog.reload_custom(defs);
            if count > 0 {
                info!(count = count, "Loaded custom services into catalog");
            }
        }

        Ok(Self {
            query_log: Arc::new(SqliteQueryLogRepository::new(
                write_pool.clone(),
                read_pool,
                db_config,
            )),
            blocklist: Arc::new(blocklist),
            blocklist_source: Arc::new(SqliteBlocklistSourceRepository::new(write_pool.clone())),
            whitelist: Arc::new(whitelist),
            whitelist_source: Arc::new(SqliteWhitelistSourceRepository::new(write_pool.clone())),
            client: Arc::new(SqliteClientRepository::new(write_pool.clone(), db_config)),
            group: Arc::new(SqliteGroupRepository::new(write_pool.clone())),
            client_subnet: Arc::new(SqliteClientSubnetRepository::new(write_pool.clone())),
            managed_domain: Arc::new(SqliteManagedDomainRepository::new(write_pool.clone())),
            regex_filter: Arc::new(SqliteRegexFilterRepository::new(write_pool.clone())),
            blocked_service: Arc::new(SqliteBlockedServiceRepository::new(write_pool)),
            custom_service,
            service_catalog,
            block_filter_engine,
        })
    }
}
