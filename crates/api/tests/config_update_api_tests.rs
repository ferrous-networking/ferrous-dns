use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::{
    create_api_routes, AppState, BlockingUseCases, ClientUseCases, DnsUseCases, GroupUseCases,
    QueryUseCases, SafeSearchUseCases, ScheduleUseCases, ServiceUseCases,
};
use ferrous_dns_application::{
    ports::{
        BlockFilterEnginePort, BlockedServiceRepository, ConfigRepository, FilterDecision,
        SafeSearchConfigRepository, SafeSearchEnginePort, ServiceCatalogPort,
    },
    use_cases::{
        AssignScheduleProfileUseCase, CreateLocalRecordUseCase, CreateScheduleProfileUseCase,
        DeleteLocalRecordUseCase, DeleteSafeSearchConfigsUseCase, DeleteScheduleProfileUseCase,
        GetBlockFilterStatsUseCase, GetBlocklistUseCase, GetClientsUseCase, GetQueryStatsUseCase,
        GetRecentQueriesUseCase, GetSafeSearchConfigsUseCase, GetScheduleProfilesUseCase,
        ManageTimeSlotsUseCase, ToggleSafeSearchUseCase, UpdateLocalRecordUseCase,
        UpdateScheduleProfileUseCase,
    },
};
use ferrous_dns_domain::{config::DatabaseConfig, Config};
use ferrous_dns_infrastructure::{
    dns::cache::DnsCache,
    repositories::{
        client_repository::SqliteClientRepository, query_log_repository::SqliteQueryLogRepository,
        regex_filter_repository::SqliteRegexFilterRepository,
    },
};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

mod helpers;

struct NullBlockFilterEngine;

#[async_trait::async_trait]
impl BlockFilterEnginePort for NullBlockFilterEngine {
    fn resolve_group(&self, _ip: std::net::IpAddr) -> i64 {
        1
    }
    fn check(&self, _domain: &str, _group_id: i64) -> FilterDecision {
        FilterDecision::Allow
    }
    async fn reload(&self) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    async fn load_client_groups(&self) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    fn compiled_domain_count(&self) -> usize {
        0
    }
    fn store_cname_decision(&self, _domain: &str, _group_id: i64, _ttl_secs: u64) {}
    fn is_blocking_enabled(&self) -> bool {
        true
    }
    fn set_blocking_enabled(&self, _enabled: bool) {}
}

struct NullBlockedServiceRepository;

#[async_trait::async_trait]
impl BlockedServiceRepository for NullBlockedServiceRepository {
    async fn block_service(
        &self,
        _service_id: &str,
        _group_id: i64,
    ) -> Result<ferrous_dns_domain::BlockedService, ferrous_dns_domain::DomainError> {
        unimplemented!()
    }
    async fn unblock_service(
        &self,
        _service_id: &str,
        _group_id: i64,
    ) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    async fn get_blocked_for_group(
        &self,
        _group_id: i64,
    ) -> Result<Vec<ferrous_dns_domain::BlockedService>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
    async fn get_all_blocked(
        &self,
    ) -> Result<Vec<ferrous_dns_domain::BlockedService>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
    async fn delete_all_for_service(
        &self,
        _service_id: &str,
    ) -> Result<u64, ferrous_dns_domain::DomainError> {
        Ok(0)
    }
}

struct NullCustomServiceRepository;

#[async_trait::async_trait]
impl ferrous_dns_application::ports::CustomServiceRepository for NullCustomServiceRepository {
    async fn create(
        &self,
        _service_id: &str,
        _name: &str,
        _category_name: &str,
        _domains: &[String],
    ) -> Result<ferrous_dns_domain::CustomService, ferrous_dns_domain::DomainError> {
        unimplemented!()
    }
    async fn get_by_service_id(
        &self,
        _service_id: &str,
    ) -> Result<Option<ferrous_dns_domain::CustomService>, ferrous_dns_domain::DomainError> {
        Ok(None)
    }
    async fn get_all(
        &self,
    ) -> Result<Vec<ferrous_dns_domain::CustomService>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
    async fn update(
        &self,
        _service_id: &str,
        _name: Option<String>,
        _category_name: Option<String>,
        _domains: Option<Vec<String>>,
    ) -> Result<ferrous_dns_domain::CustomService, ferrous_dns_domain::DomainError> {
        unimplemented!()
    }
    async fn delete(&self, _service_id: &str) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
}

struct NullServiceCatalog;

impl ServiceCatalogPort for NullServiceCatalog {
    fn get_by_id(&self, _id: &str) -> Option<ferrous_dns_domain::ServiceDefinition> {
        None
    }
    fn all(&self) -> Vec<ferrous_dns_domain::ServiceDefinition> {
        vec![]
    }
    fn normalized_rules_for(&self, _service_id: &str) -> Vec<String> {
        vec![]
    }
    fn reload_custom(&self, _custom: Vec<ferrous_dns_domain::ServiceDefinition>) {}
}
struct NullConfigRepository;
#[async_trait::async_trait]
impl ConfigRepository for NullConfigRepository {
    async fn save_local_records(
        &self,
        _config: &Config,
    ) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
}

struct NullSafeSearchConfigRepository;
#[async_trait::async_trait]
impl SafeSearchConfigRepository for NullSafeSearchConfigRepository {
    async fn get_all(
        &self,
    ) -> Result<Vec<ferrous_dns_domain::SafeSearchConfig>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
    async fn get_by_group(
        &self,
        _group_id: i64,
    ) -> Result<Vec<ferrous_dns_domain::SafeSearchConfig>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
    async fn upsert(
        &self,
        _group_id: i64,
        _engine: ferrous_dns_domain::SafeSearchEngine,
        _enabled: bool,
        _youtube_mode: ferrous_dns_domain::YouTubeMode,
    ) -> Result<ferrous_dns_domain::SafeSearchConfig, ferrous_dns_domain::DomainError> {
        unimplemented!()
    }
    async fn delete_by_group(&self, _group_id: i64) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
}

struct NullSafeSearchEnginePort;
#[async_trait::async_trait]
impl SafeSearchEnginePort for NullSafeSearchEnginePort {
    fn cname_for(&self, _domain: &str, _group_id: i64) -> Option<&'static str> {
        None
    }
    async fn reload(&self) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
}

struct NullScheduleProfileRepository;

#[async_trait::async_trait]
impl ferrous_dns_application::ports::ScheduleProfileRepository for NullScheduleProfileRepository {
    async fn create(
        &self,
        _name: String,
        _tz: String,
        _comment: Option<String>,
    ) -> Result<ferrous_dns_domain::ScheduleProfile, ferrous_dns_domain::DomainError> {
        unimplemented!()
    }
    async fn get_by_id(
        &self,
        _id: i64,
    ) -> Result<Option<ferrous_dns_domain::ScheduleProfile>, ferrous_dns_domain::DomainError> {
        Ok(None)
    }
    async fn get_all(
        &self,
    ) -> Result<Vec<ferrous_dns_domain::ScheduleProfile>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
    async fn update(
        &self,
        _id: i64,
        _name: Option<String>,
        _tz: Option<String>,
        _comment: Option<String>,
    ) -> Result<ferrous_dns_domain::ScheduleProfile, ferrous_dns_domain::DomainError> {
        unimplemented!()
    }
    async fn delete(&self, _id: i64) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    async fn get_slots(
        &self,
        _profile_id: i64,
    ) -> Result<Vec<ferrous_dns_domain::TimeSlot>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
    async fn add_slot(
        &self,
        _pid: i64,
        _days: u8,
        _start: String,
        _end: String,
        _action: ferrous_dns_domain::ScheduleAction,
    ) -> Result<ferrous_dns_domain::TimeSlot, ferrous_dns_domain::DomainError> {
        unimplemented!()
    }
    async fn delete_slot(&self, _slot_id: i64) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    async fn assign_to_group(
        &self,
        _group_id: i64,
        _profile_id: i64,
    ) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    async fn unassign_from_group(
        &self,
        _group_id: i64,
    ) -> Result<(), ferrous_dns_domain::DomainError> {
        Ok(())
    }
    async fn get_group_assignment(
        &self,
        _group_id: i64,
    ) -> Result<Option<i64>, ferrous_dns_domain::DomainError> {
        Ok(None)
    }
    async fn get_all_group_assignments(
        &self,
    ) -> Result<Vec<(i64, i64)>, ferrous_dns_domain::DomainError> {
        Ok(vec![])
    }
}

async fn create_test_db() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            comment TEXT,
            is_default BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        INSERT INTO groups (id, name, enabled, comment, is_default)
        VALUES (1, 'Protected', 1, 'Default group', 1)
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            mac_address TEXT,
            hostname TEXT,
            first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            query_count INTEGER NOT NULL DEFAULT 0,
            last_mac_update DATETIME,
            last_hostname_update DATETIME,
            group_id INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE regex_filters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            pattern TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('allow', 'deny')),
            group_id INTEGER NOT NULL DEFAULT 1,
            comment TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            record_type TEXT NOT NULL DEFAULT 'A',
            client_ip TEXT NOT NULL DEFAULT '127.0.0.1',
            blocked INTEGER NOT NULL DEFAULT 0,
            response_time_ms INTEGER,
            cache_hit INTEGER NOT NULL DEFAULT 0,
            cache_refresh INTEGER NOT NULL DEFAULT 0,
            dnssec_status TEXT,
            upstream_server TEXT,
            upstream_pool TEXT,
            response_status TEXT,
            query_source TEXT NOT NULL DEFAULT 'client',
            group_id INTEGER,
            block_source TEXT,
            created_at DATETIME NOT NULL DEFAULT (datetime('now'))
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    pool
}

/// Builds the API router plus a handle to the live `PoolManager` (to assert hot
/// reloads) and a writable temp config path (the update handler refuses to run
/// without one). The temp file is created empty and is overwritten on save.
async fn create_test_app(
    pool: sqlx::SqlitePool,
) -> (
    Router,
    Arc<ferrous_dns_infrastructure::dns::PoolManager>,
    String,
) {
    let client_repo = Arc::new(SqliteClientRepository::new(
        pool.clone(),
        &DatabaseConfig::default(),
    ));
    let group_repo = Arc::new(
        ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository::new(
            pool.clone(),
        ),
    );
    let regex_filter_repo = Arc::new(SqliteRegexFilterRepository::new(pool.clone()));
    let query_log_repo = Arc::new(SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &DatabaseConfig::default(),
    ));

    let config = Arc::new(RwLock::new(Config::default()));
    let cache = Arc::new(DnsCache::new(
        ferrous_dns_infrastructure::dns::DnsCacheConfig {
            max_entries: 0,
            eviction_strategy: ferrous_dns_infrastructure::dns::EvictionStrategy::LRU,
            min_threshold: 0.0,
            refresh_threshold: 0.0,
            batch_eviction_percentage: 0.0,
            adaptive_thresholds: false,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 7200,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
            min_ttl: 0,
            max_ttl: 86_400,
        },
    ));

    use ferrous_dns_domain::config::upstream::{UpstreamPool, UpstreamStrategy};
    use ferrous_dns_infrastructure::dns::{PoolManager, QueryEventEmitter};

    let event_emitter = QueryEventEmitter::new_disabled();
    let test_pool = UpstreamPool {
        name: "test".to_string(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec!["8.8.8.8:53".to_string()],
        weight: None,
    };
    let pool_manager = Arc::new(
        PoolManager::new(vec![test_pool], None, event_emitter)
            .await
            .expect("Failed to create PoolManager"),
    );
    let pool_manager_handle = pool_manager.clone();

    // The update handler resolves a config path up front and refuses to run
    // without one, so point it at a unique writable temp file.
    let config_path = std::env::temp_dir()
        .join(format!(
            "ferrous_cfg_update_test_{}_{}.toml",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
        .to_string_lossy()
        .into_owned();
    std::fs::write(&config_path, "").unwrap();

    let state = AppState {
        query: QueryUseCases {
            get_stats: Arc::new(GetQueryStatsUseCase::new(query_log_repo.clone(), client_repo.clone())),
            get_queries: Arc::new(GetRecentQueriesUseCase::new(query_log_repo.clone())),
            get_timeline: Arc::new(ferrous_dns_application::use_cases::GetTimelineUseCase::new(query_log_repo.clone())),
            get_query_rate: Arc::new(ferrous_dns_application::use_cases::GetQueryRateUseCase::new(query_log_repo.clone())),
            get_cache_stats: Arc::new(ferrous_dns_application::use_cases::GetCacheStatsUseCase::new(query_log_repo.clone())),
            get_top_blocked_domains: Arc::new(ferrous_dns_application::use_cases::GetTopBlockedDomainsUseCase::new(query_log_repo.clone())),
            get_top_clients: Arc::new(ferrous_dns_application::use_cases::GetTopClientsUseCase::new(query_log_repo.clone())),
        },
        dns: DnsUseCases {
            cache: cache as Arc<dyn ferrous_dns_application::ports::DnsCachePort>,
            create_local_record: Arc::new(CreateLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository))),
            update_local_record: Arc::new(UpdateLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository))),
            delete_local_record: Arc::new(DeleteLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository))),
            upstream_health: Arc::new(ferrous_dns_infrastructure::dns::UpstreamHealthAdapter::new(
                pool_manager.clone(),
                None,
            )),
            reload_upstream: Arc::new(ferrous_dns_infrastructure::dns::UpstreamReloadAdapter::new(vec![pool_manager.clone(), pool_manager])),
        },
        groups: GroupUseCases {
            get_groups: Arc::new(ferrous_dns_application::use_cases::GetGroupsUseCase::new(group_repo.clone())),
            create_group: Arc::new(ferrous_dns_application::use_cases::CreateGroupUseCase::new(group_repo.clone())),
            update_group: Arc::new(ferrous_dns_application::use_cases::UpdateGroupUseCase::new(group_repo.clone())),
            delete_group: Arc::new(ferrous_dns_application::use_cases::DeleteGroupUseCase::new(group_repo.clone())),
            assign_client_group: Arc::new(ferrous_dns_application::use_cases::AssignClientGroupUseCase::new(
                client_repo.clone(),
                group_repo.clone(),
                Arc::new(NullBlockFilterEngine),
            )),
        },
        clients: ClientUseCases {
            get_clients: Arc::new(GetClientsUseCase::new(client_repo.clone())),
            get_client_subnets: Arc::new(ferrous_dns_application::use_cases::GetClientSubnetsUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone()),
            ))),
            create_client_subnet: Arc::new(ferrous_dns_application::use_cases::CreateClientSubnetUseCase::new(
                Arc::new(ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone())),
                group_repo.clone(),
                Arc::new(NullBlockFilterEngine),
            )),
            delete_client_subnet: Arc::new(ferrous_dns_application::use_cases::DeleteClientSubnetUseCase::new(
                Arc::new(ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone())),
                Arc::new(NullBlockFilterEngine),
            )),
            create_manual_client: Arc::new(ferrous_dns_application::use_cases::CreateManualClientUseCase::new(
                client_repo.clone(),
                group_repo.clone(),
            )),
            update_client: Arc::new(ferrous_dns_application::use_cases::UpdateClientUseCase::new(client_repo.clone())),
            delete_client: Arc::new(ferrous_dns_application::use_cases::DeleteClientUseCase::new(client_repo.clone())),
            subnet_matcher: Arc::new(ferrous_dns_application::services::SubnetMatcherService::new(Arc::new(
                ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository::new(pool.clone()),
            ))),
        },
        blocking: BlockingUseCases {
            get_blocklist: Arc::new(GetBlocklistUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository::new(pool.clone()),
            ))),
            get_blocklist_sources: Arc::new(ferrous_dns_application::use_cases::GetBlocklistSourcesUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone()),
            ))),
            create_blocklist_source: Arc::new(ferrous_dns_application::use_cases::CreateBlocklistSourceUseCase::new(
                Arc::new(ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone())),
                group_repo.clone(),
            )),
            update_blocklist_source: Arc::new(ferrous_dns_application::use_cases::UpdateBlocklistSourceUseCase::new(
                Arc::new(ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone())),
                group_repo.clone(),
            )),
            delete_blocklist_source: Arc::new(ferrous_dns_application::use_cases::DeleteBlocklistSourceUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository::new(pool.clone()),
            ))),
            get_whitelist: Arc::new(ferrous_dns_application::use_cases::GetWhitelistUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::whitelist_repository::SqliteWhitelistRepository::new(pool.clone()),
            ))),
            get_whitelist_sources: Arc::new(ferrous_dns_application::use_cases::GetWhitelistSourcesUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository::new(pool.clone()),
            ))),
            create_whitelist_source: Arc::new(ferrous_dns_application::use_cases::CreateWhitelistSourceUseCase::new(
                Arc::new(ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository::new(pool.clone())),
                group_repo.clone(),
            )),
            update_whitelist_source: Arc::new(ferrous_dns_application::use_cases::UpdateWhitelistSourceUseCase::new(
                Arc::new(ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository::new(pool.clone())),
                group_repo.clone(),
            )),
            delete_whitelist_source: Arc::new(ferrous_dns_application::use_cases::DeleteWhitelistSourceUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository::new(pool.clone()),
            ))),
            get_managed_domains: Arc::new(ferrous_dns_application::use_cases::GetManagedDomainsUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone()),
            ))),
            create_managed_domain: Arc::new(ferrous_dns_application::use_cases::CreateManagedDomainUseCase::new(
                Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
                group_repo.clone(),
                Arc::new(NullBlockFilterEngine),
            )),
            update_managed_domain: Arc::new(ferrous_dns_application::use_cases::UpdateManagedDomainUseCase::new(
                Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
                group_repo.clone(),
                Arc::new(NullBlockFilterEngine),
            )),
            delete_managed_domain: Arc::new(ferrous_dns_application::use_cases::DeleteManagedDomainUseCase::new(
                Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
                Arc::new(NullBlockFilterEngine),
            )),
            get_regex_filters: Arc::new(ferrous_dns_application::use_cases::GetRegexFiltersUseCase::new(
                regex_filter_repo.clone(),
            )),
            create_regex_filter: Arc::new(ferrous_dns_application::use_cases::CreateRegexFilterUseCase::new(
                regex_filter_repo.clone(),
                group_repo.clone(),
                Arc::new(NullBlockFilterEngine),
            )),
            update_regex_filter: Arc::new(ferrous_dns_application::use_cases::UpdateRegexFilterUseCase::new(
                regex_filter_repo.clone(),
                group_repo.clone(),
                Arc::new(NullBlockFilterEngine),
            )),
            delete_regex_filter: Arc::new(ferrous_dns_application::use_cases::DeleteRegexFilterUseCase::new(
                regex_filter_repo.clone(),
                Arc::new(NullBlockFilterEngine),
            )),
            get_block_filter_stats: Arc::new(GetBlockFilterStatsUseCase::new(Arc::new(NullBlockFilterEngine))),
            test_domain: Arc::new(ferrous_dns_application::use_cases::TestDomainUseCase::new(Arc::new(NullBlockFilterEngine))),
            backtest: Arc::new(ferrous_dns_application::use_cases::BacktestBlocklistsUseCase::new(
                Arc::new(NullBlockFilterEngine),
                Arc::new(ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(pool.clone(), pool.clone(), pool.clone(), &Default::default())),
            )),
        },
        services: ServiceUseCases {
            get_service_catalog: Arc::new(ferrous_dns_application::use_cases::GetServiceCatalogUseCase::new(Arc::new(NullServiceCatalog))),
            get_blocked_services: Arc::new(ferrous_dns_application::use_cases::GetBlockedServicesUseCase::new(Arc::new(NullBlockedServiceRepository))),
            block_service: Arc::new(ferrous_dns_application::use_cases::BlockServiceUseCase::new(
                Arc::new(NullBlockedServiceRepository),
                Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
                group_repo.clone(),
                Arc::new(NullBlockFilterEngine),
                Arc::new(NullServiceCatalog),
            )),
            unblock_service: Arc::new(ferrous_dns_application::use_cases::UnblockServiceUseCase::new(
                Arc::new(NullBlockedServiceRepository),
                Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())),
                Arc::new(NullBlockFilterEngine),
            )),
            create_custom_service: Arc::new(ferrous_dns_application::use_cases::CreateCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog))),
            get_custom_services: Arc::new(ferrous_dns_application::use_cases::GetCustomServicesUseCase::new(Arc::new(NullCustomServiceRepository))),
            update_custom_service: Arc::new(ferrous_dns_application::use_cases::UpdateCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog), Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())), Arc::new(NullBlockedServiceRepository), Arc::new(NullBlockFilterEngine))),
            delete_custom_service: Arc::new(ferrous_dns_application::use_cases::DeleteCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog), Arc::new(NullBlockedServiceRepository), Arc::new(ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository::new(pool.clone())), Arc::new(NullBlockFilterEngine))),
        },
        safe_search: SafeSearchUseCases {
            get_configs: Arc::new(GetSafeSearchConfigsUseCase::new(
                Arc::new(NullSafeSearchConfigRepository),
                group_repo.clone(),
            )),
            toggle: Arc::new(ToggleSafeSearchUseCase::new(
                Arc::new(NullSafeSearchConfigRepository),
                group_repo.clone(),
                Arc::new(NullSafeSearchEnginePort),
            )),
            delete_configs: Arc::new(DeleteSafeSearchConfigsUseCase::new(
                Arc::new(NullSafeSearchConfigRepository),
                group_repo.clone(),
                Arc::new(NullSafeSearchEnginePort),
            )),
        },
        schedule: ScheduleUseCases {
            get_profiles: Arc::new(GetScheduleProfilesUseCase::new(Arc::new(NullScheduleProfileRepository))),
            create_profile: Arc::new(CreateScheduleProfileUseCase::new(Arc::new(NullScheduleProfileRepository))),
            update_profile: Arc::new(UpdateScheduleProfileUseCase::new(Arc::new(NullScheduleProfileRepository))),
            delete_profile: Arc::new(DeleteScheduleProfileUseCase::new(Arc::new(NullScheduleProfileRepository))),
            manage_slots: Arc::new(ManageTimeSlotsUseCase::new(Arc::new(NullScheduleProfileRepository))),
            assign_profile: Arc::new(AssignScheduleProfileUseCase::new(Arc::new(NullScheduleProfileRepository), group_repo.clone())),
        },
        auth: helpers::build_test_auth_use_cases(),
        backup: helpers::build_test_backup_use_cases(config.clone()),
        config: config.clone(),
        config_file_persistence: Arc::new(ferrous_dns_infrastructure::repositories::TomlConfigFilePersistence),
        config_path: Some(Arc::from(config_path.as_str())),
        tls_cert: Arc::new(helpers::MockTlsCertificateService),
        tls_enabled: false,
    };

    (create_api_routes(state), pool_manager_handle, config_path)
}

async fn post_config(app: Router, body: serde_json::Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/config")
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

fn live_servers(pm: &ferrous_dns_infrastructure::dns::PoolManager) -> Vec<String> {
    pm.get_all_servers().iter().map(|a| a.to_string()).collect()
}

#[tokio::test]
async fn test_update_config_rejects_invalid_server() {
    let pool = create_test_db().await;
    let (app, pm, _path) = create_test_app(pool).await;

    let (status, json) = post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["not-a-valid-endpoint"] }
            ] }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], false);
    assert!(
        json["error"].as_str().unwrap().contains("Invalid server"),
        "error should name the bad server, got: {}",
        json["error"]
    );
    // A rejected save must not touch the live pools.
    assert!(live_servers(&pm).iter().any(|s| s == "8.8.8.8:53"));
}

#[tokio::test]
async fn test_update_config_rejects_pool_with_only_blank_servers() {
    let pool = create_test_db().await;
    let (app, pm, _path) = create_test_app(pool).await;

    let (status, json) = post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["", "   "] }
            ] }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], false);
    assert!(
        json["error"]
            .as_str()
            .unwrap()
            .contains("At least one pool"),
        "blank-only servers should leave zero valid pools, got: {}",
        json["error"]
    );
    assert!(live_servers(&pm).iter().any(|s| s == "8.8.8.8:53"));
}

#[tokio::test]
async fn test_update_config_hot_applies_valid_pools_without_restart() {
    let pool = create_test_db().await;
    let (app, pm, _path) = create_test_app(pool).await;

    let (status, json) = post_config(
        app,
        serde_json::json!({
            "dns": { "pools": [
                { "name": "p1", "strategy": "parallel", "priority": 1,
                  "servers": ["udp://9.9.9.9:53"] }
            ] }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    // Pool-only changes are hot-applied; no restart banner.
    assert_eq!(json["restart_required"], false);

    // The live pool manager must already serve the new upstream.
    let servers = live_servers(&pm);
    assert!(
        servers.iter().any(|s| s == "9.9.9.9:53"),
        "new upstream should be live after save: {servers:?}"
    );
    assert!(
        !servers.iter().any(|s| s == "8.8.8.8:53"),
        "old upstream should be gone after hot reload: {servers:?}"
    );
}

#[tokio::test]
async fn test_update_config_non_pool_change_requires_restart() {
    let pool = create_test_db().await;
    let (app, pm, _path) = create_test_app(pool).await;

    // pihole_compat defaults to false; flipping it is a non-hot-applied change.
    let (status, json) = post_config(
        app,
        serde_json::json!({ "server": { "pihole_compat": true } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["success"], true);
    assert_eq!(
        json["restart_required"], true,
        "a non-pool field change must ask for a restart"
    );
    // No pools were sent, so the live pool set is untouched.
    assert!(live_servers(&pm).iter().any(|s| s == "8.8.8.8:53"));
}
