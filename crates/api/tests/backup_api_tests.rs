use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use ferrous_dns_api::{
    create_api_routes, AppState, BackupUseCases, BlockingUseCases, ClientUseCases, DnsUseCases,
    GroupUseCases, QueryUseCases, SafeSearchUseCases, ScheduleUseCases, ServiceUseCases,
};
use ferrous_dns_application::ports::{BlocklistSourceCreator, GroupCreator, LocalRecordCreator};
use ferrous_dns_application::{
    ports::{
        BlockFilterEnginePort, BlockedServiceRepository, ConfigFilePersistence, ConfigRepository,
        FilterDecision, SafeSearchConfigRepository, SafeSearchEnginePort, ServiceCatalogPort,
    },
    services::SubnetMatcherService,
    use_cases::{
        AssignScheduleProfileUseCase, CreateBlocklistSourceUseCase, CreateGroupUseCase,
        CreateLocalRecordUseCase, CreateScheduleProfileUseCase, DeleteScheduleProfileUseCase,
        ExportConfigUseCase, GetBlockFilterStatsUseCase, GetScheduleProfilesUseCase,
        ImportConfigUseCase, ManageTimeSlotsUseCase, UpdateScheduleProfileUseCase, *,
    },
};
use ferrous_dns_domain::{config::DatabaseConfig, Config, LocalDnsRecord};
use ferrous_dns_infrastructure::{
    dns::cache::DnsCache,
    repositories::{
        blocklist_source_repository::SqliteBlocklistSourceRepository,
        client_repository::SqliteClientRepository,
        client_subnet_repository::SqliteClientSubnetRepository,
        group_repository::SqliteGroupRepository,
        managed_domain_repository::SqliteManagedDomainRepository,
        regex_filter_repository::SqliteRegexFilterRepository,
    },
};
use http_body_util::BodyExt;
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

mod helpers;

// ── Null stubs (mesmos das outros arquivos de teste) ─────────────────────────

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

struct NullConfigFilePersistence;

impl ConfigFilePersistence for NullConfigFilePersistence {
    fn save_config_to_file(&self, _config: &Config, _path: &str) -> Result<(), String> {
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

// ── DB setup ─────────────────────────────────────────────────────────────────

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

    sqlx::query("INSERT INTO groups (id, name, is_default) VALUES (1, 'Protected', 1)")
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
        CREATE TABLE client_subnets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subnet_cidr TEXT NOT NULL UNIQUE,
            group_id INTEGER NOT NULL,
            comment TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE blocklist_sources (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            url         TEXT,
            group_id    INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT,
            comment     TEXT,
            enabled     BOOLEAN NOT NULL DEFAULT 1,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE blocklist_source_groups (
            source_id INTEGER NOT NULL REFERENCES blocklist_sources(id) ON DELETE CASCADE,
            group_id  INTEGER NOT NULL REFERENCES groups(id)            ON DELETE CASCADE,
            PRIMARY KEY (source_id, group_id)
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            source_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            comment TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE whitelist_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            url TEXT,
            comment TEXT,
            enabled BOOLEAN NOT NULL DEFAULT 1,
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
        CREATE TABLE whitelist_source_groups (
            source_id INTEGER NOT NULL REFERENCES whitelist_sources(id) ON DELETE CASCADE,
            group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            PRIMARY KEY (source_id, group_id)
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    sqlx::query(
        r#"
        CREATE TABLE managed_domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            domain TEXT NOT NULL,
            action TEXT NOT NULL CHECK(action IN ('allow', 'deny')),
            group_id INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id),
            comment TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            service_id TEXT,
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
            query_type TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            status TEXT NOT NULL,
            response_time_ms INTEGER,
            blocked_by TEXT,
            upstream TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        "#,
    )
    .execute(&pool)
    .await
    .unwrap();

    pool
}

// ── App factory ──────────────────────────────────────────────────────────────

async fn create_test_app() -> (Router, Arc<RwLock<Config>>, sqlx::SqlitePool) {
    let pool = create_test_db().await;

    let client_repo = Arc::new(SqliteClientRepository::new(
        pool.clone(),
        &DatabaseConfig::default(),
    ));
    let group_repo = Arc::new(SqliteGroupRepository::new(pool.clone()));
    let subnet_repo = Arc::new(SqliteClientSubnetRepository::new(pool.clone()));
    let managed_domain_repo = Arc::new(SqliteManagedDomainRepository::new(pool.clone()));
    let regex_filter_repo = Arc::new(SqliteRegexFilterRepository::new(pool.clone()));
    let blocklist_source_repo = Arc::new(SqliteBlocklistSourceRepository::new(pool.clone()));
    let null_engine: Arc<dyn BlockFilterEnginePort> = Arc::new(NullBlockFilterEngine);
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

    // Backup use cases com repositórios reais para testes completos
    let group_creator: Arc<dyn GroupCreator> = Arc::new(CreateGroupUseCase::new(
        group_repo.clone() as Arc<dyn ferrous_dns_application::ports::GroupRepository>,
    ));
    let blocklist_source_creator: Arc<dyn BlocklistSourceCreator> =
        Arc::new(CreateBlocklistSourceUseCase::new(
            blocklist_source_repo.clone()
                as Arc<dyn ferrous_dns_application::ports::BlocklistSourceRepository>,
            group_repo.clone() as Arc<dyn ferrous_dns_application::ports::GroupRepository>,
        ));
    let local_record_creator: Arc<dyn LocalRecordCreator> = Arc::new(
        CreateLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository)),
    );

    let backup = BackupUseCases {
        export: Arc::new(ExportConfigUseCase::new(
            config.clone(),
            group_repo.clone() as Arc<dyn ferrous_dns_application::ports::GroupRepository>,
            blocklist_source_repo.clone()
                as Arc<dyn ferrous_dns_application::ports::BlocklistSourceRepository>,
        )),
        import: Arc::new(ImportConfigUseCase::new(
            config.clone(),
            Arc::new(NullConfigFilePersistence),
            Some("ferrous-dns.toml".to_string()),
            group_creator,
            blocklist_source_creator,
            local_record_creator,
        )),
    };

    let ql_repo = || {
        Arc::new(ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository::new(
            pool.clone(), pool.clone(), pool.clone(), &DatabaseConfig::default(),
        ))
    };

    let state = AppState {
        query: QueryUseCases {
            get_stats: Arc::new(GetQueryStatsUseCase::new(ql_repo(), client_repo.clone())),
            get_queries: Arc::new(GetRecentQueriesUseCase::new(ql_repo())),
            get_timeline: Arc::new(ferrous_dns_application::use_cases::GetTimelineUseCase::new(ql_repo())),
            get_query_rate: Arc::new(ferrous_dns_application::use_cases::GetQueryRateUseCase::new(ql_repo())),
            get_cache_stats: Arc::new(ferrous_dns_application::use_cases::GetCacheStatsUseCase::new(ql_repo())),
            get_top_blocked_domains: Arc::new(ferrous_dns_application::use_cases::GetTopBlockedDomainsUseCase::new(ql_repo())),
            get_top_clients: Arc::new(ferrous_dns_application::use_cases::GetTopClientsUseCase::new(ql_repo())),
        },
        dns: DnsUseCases {
            cache: cache as Arc<dyn ferrous_dns_application::ports::DnsCachePort>,
            create_local_record: Arc::new(CreateLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository))),
            update_local_record: Arc::new(UpdateLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository))),
            delete_local_record: Arc::new(DeleteLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository))),
            upstream_health: Arc::new(ferrous_dns_infrastructure::dns::UpstreamHealthAdapter::new(pool_manager, None)),
        },
        groups: GroupUseCases {
            get_groups: Arc::new(GetGroupsUseCase::new(group_repo.clone())),
            create_group: Arc::new(CreateGroupUseCase::new(group_repo.clone())),
            update_group: Arc::new(UpdateGroupUseCase::new(group_repo.clone())),
            delete_group: Arc::new(DeleteGroupUseCase::new(group_repo.clone())),
            assign_client_group: Arc::new(AssignClientGroupUseCase::new(client_repo.clone(), group_repo.clone(), Arc::new(NullBlockFilterEngine))),
        },
        clients: ClientUseCases {
            get_clients: Arc::new(GetClientsUseCase::new(client_repo.clone())),
            get_client_subnets: Arc::new(GetClientSubnetsUseCase::new(subnet_repo.clone())),
            create_client_subnet: Arc::new(CreateClientSubnetUseCase::new(subnet_repo.clone(), group_repo.clone(), Arc::new(NullBlockFilterEngine))),
            delete_client_subnet: Arc::new(DeleteClientSubnetUseCase::new(subnet_repo.clone(), Arc::new(NullBlockFilterEngine))),
            create_manual_client: Arc::new(CreateManualClientUseCase::new(client_repo.clone(), group_repo.clone())),
            update_client: Arc::new(UpdateClientUseCase::new(client_repo.clone())),
            delete_client: Arc::new(DeleteClientUseCase::new(client_repo.clone())),
            subnet_matcher: Arc::new(SubnetMatcherService::new(subnet_repo.clone())),
        },
        blocking: BlockingUseCases {
            get_blocklist: Arc::new(GetBlocklistUseCase::new(Arc::new(
                ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository::new(pool.clone()),
            ))),
            get_blocklist_sources: Arc::new(GetBlocklistSourcesUseCase::new(blocklist_source_repo.clone())),
            create_blocklist_source: Arc::new(CreateBlocklistSourceUseCase::new(blocklist_source_repo.clone(), group_repo.clone())),
            update_blocklist_source: Arc::new(UpdateBlocklistSourceUseCase::new(blocklist_source_repo.clone(), group_repo.clone())),
            delete_blocklist_source: Arc::new(DeleteBlocklistSourceUseCase::new(blocklist_source_repo.clone())),
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
            get_managed_domains: Arc::new(GetManagedDomainsUseCase::new(managed_domain_repo.clone())),
            create_managed_domain: Arc::new(CreateManagedDomainUseCase::new(managed_domain_repo.clone(), group_repo.clone(), null_engine.clone())),
            update_managed_domain: Arc::new(UpdateManagedDomainUseCase::new(managed_domain_repo.clone(), group_repo.clone(), null_engine.clone())),
            delete_managed_domain: Arc::new(DeleteManagedDomainUseCase::new(managed_domain_repo.clone(), null_engine.clone())),
            get_regex_filters: Arc::new(ferrous_dns_application::use_cases::GetRegexFiltersUseCase::new(regex_filter_repo.clone())),
            create_regex_filter: Arc::new(ferrous_dns_application::use_cases::CreateRegexFilterUseCase::new(regex_filter_repo.clone(), group_repo.clone(), null_engine.clone())),
            update_regex_filter: Arc::new(ferrous_dns_application::use_cases::UpdateRegexFilterUseCase::new(regex_filter_repo.clone(), group_repo.clone(), null_engine.clone())),
            delete_regex_filter: Arc::new(ferrous_dns_application::use_cases::DeleteRegexFilterUseCase::new(regex_filter_repo.clone(), null_engine.clone())),
            get_block_filter_stats: Arc::new(GetBlockFilterStatsUseCase::new(Arc::new(NullBlockFilterEngine))),
        },
        services: ServiceUseCases {
            get_service_catalog: Arc::new(GetServiceCatalogUseCase::new(Arc::new(NullServiceCatalog))),
            get_blocked_services: Arc::new(GetBlockedServicesUseCase::new(Arc::new(NullBlockedServiceRepository))),
            block_service: Arc::new(BlockServiceUseCase::new(Arc::new(NullBlockedServiceRepository), managed_domain_repo.clone(), group_repo.clone(), null_engine.clone(), Arc::new(NullServiceCatalog))),
            unblock_service: Arc::new(UnblockServiceUseCase::new(Arc::new(NullBlockedServiceRepository), managed_domain_repo.clone(), null_engine.clone())),
            create_custom_service: Arc::new(ferrous_dns_application::use_cases::CreateCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog))),
            get_custom_services: Arc::new(ferrous_dns_application::use_cases::GetCustomServicesUseCase::new(Arc::new(NullCustomServiceRepository))),
            update_custom_service: Arc::new(ferrous_dns_application::use_cases::UpdateCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog), managed_domain_repo.clone(), Arc::new(NullBlockedServiceRepository), null_engine.clone())),
            delete_custom_service: Arc::new(ferrous_dns_application::use_cases::DeleteCustomServiceUseCase::new(Arc::new(NullCustomServiceRepository), Arc::new(NullServiceCatalog), Arc::new(NullBlockedServiceRepository), managed_domain_repo.clone(), null_engine.clone())),
        },
        safe_search: SafeSearchUseCases {
            get_configs: Arc::new(GetSafeSearchConfigsUseCase::new(Arc::new(NullSafeSearchConfigRepository), group_repo.clone())),
            toggle: Arc::new(ToggleSafeSearchUseCase::new(Arc::new(NullSafeSearchConfigRepository), group_repo.clone(), Arc::new(NullSafeSearchEnginePort))),
            delete_configs: Arc::new(DeleteSafeSearchConfigsUseCase::new(Arc::new(NullSafeSearchConfigRepository), group_repo.clone(), Arc::new(NullSafeSearchEnginePort))),
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
        backup,
        config: config.clone(),
        config_file_persistence: Arc::new(ferrous_dns_infrastructure::repositories::TomlConfigFilePersistence),
        config_path: None,
        tls_cert: Arc::new(helpers::MockTlsCertificateService),
        tls_enabled: false,
    };

    let app = create_api_routes(state);
    (app, config, pool)
}

// ── Helpers de requisição ─────────────────────────────────────────────────────

fn build_multipart_body(boundary: &str, json_bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"backup.json\"\r\nContent-Type: application/json\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(json_bytes);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    body
}

fn import_request(json_bytes: &[u8]) -> Request<Body> {
    let boundary = "testboundary";
    let body = build_multipart_body(boundary, json_bytes);
    Request::builder()
        .uri("/config/import")
        .method("POST")
        .header(
            "content-type",
            format!("multipart/form-data; boundary={boundary}"),
        )
        .body(Body::from(body))
        .unwrap()
}

fn minimal_backup_json() -> Value {
    json!({
        "version": "1",
        "ferrous_version": "0.8.2",
        "exported_at": "2026-04-20T10:00:00Z",
        "config": {
            "server": { "dns_port": 53, "web_port": 8080, "bind_address": "0.0.0.0", "pihole_compat": false, "tls_cert_path": "", "tls_key_path": "", "tls_enabled": false },
            "dns": {
                "upstream_servers": [], "cache_enabled": true, "dnssec_enabled": false,
                "cache_eviction_strategy": "hit_rate", "cache_max_entries": 10000,
                "cache_min_hit_rate": 2.0, "cache_min_frequency": 10, "cache_min_lfuk_score": 1.5,
                "cache_compaction_interval": 600, "cache_refresh_threshold": 0.75,
                "cache_optimistic_refresh": true, "cache_adaptive_thresholds": false,
                "cache_access_window_secs": 43200, "cache_min_ttl": 60, "cache_max_ttl": 86400,
                "block_non_fqdn": true, "block_private_ptr": true,
                "local_domain": null, "local_dns_server": null
            },
            "blocking": { "enabled": false, "custom_blocked": [], "whitelist": [] },
            "logging": { "level": "info" },
            "auth": { "enabled": false, "session_ttl_hours": 24, "remember_me_days": 30, "login_rate_limit_attempts": 5, "login_rate_limit_window_secs": 900 }
        },
        "data": {
            "groups": [],
            "blocklist_sources": [],
            "local_records": []
        }
    })
}

async fn do_export(app: Router) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .uri("/config/export")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let status = response.status();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    (status, json)
}

// ── Testes de Export ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_export_returns_200() {
    let (app, _config, _pool) = create_test_app().await;
    let (status, _) = do_export(app).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_export_response_is_valid_json() {
    let (app, _config, _pool) = create_test_app().await;
    let (_, json) = do_export(app).await;
    assert!(json.is_object());
    assert!(json.get("version").is_some());
    assert!(json.get("ferrous_version").is_some());
    assert!(json.get("exported_at").is_some());
    assert!(json.get("config").is_some());
    assert!(json.get("data").is_some());
}

#[tokio::test]
async fn test_export_version_is_one() {
    let (app, _config, _pool) = create_test_app().await;
    let (_, json) = do_export(app).await;
    assert_eq!(json["version"], "1");
}

#[tokio::test]
async fn test_export_does_not_expose_password_hash() {
    let (app, _config, _pool) = create_test_app().await;
    let (_, json) = do_export(app).await;
    let raw = serde_json::to_string(&json).unwrap();
    assert!(
        !raw.contains("password_hash"),
        "password_hash must never appear in the export"
    );
}

#[tokio::test]
async fn test_export_local_records_empty_when_config_has_none() {
    let (app, _config, _pool) = create_test_app().await;
    let (_, json) = do_export(app).await;
    let records = json["data"]["local_records"].as_array().unwrap();
    assert_eq!(records.len(), 0);
}

#[tokio::test]
async fn test_export_includes_local_records_from_config() {
    let (app, config, _pool) = create_test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "nas".to_string(),
            domain: Some("home".to_string()),
            ip: "192.168.1.100".to_string(),
            record_type: "A".to_string(),
            ttl: Some(300),
        });
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "pi".to_string(),
            domain: Some("home".to_string()),
            ip: "192.168.1.5".to_string(),
            record_type: "A".to_string(),
            ttl: Some(60),
        });
    }

    let (_, json) = do_export(app).await;
    let records = json["data"]["local_records"].as_array().unwrap();

    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["hostname"], "nas");
    assert_eq!(records[0]["ip"], "192.168.1.100");
    assert_eq!(records[1]["hostname"], "pi");
}

#[tokio::test]
async fn test_export_includes_groups_from_database() {
    let (app, _config, _pool) = create_test_app().await;
    let (_, json) = do_export(app).await;

    let groups = json["data"]["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0]["name"], "Protected");
}

#[tokio::test]
async fn test_export_content_disposition_header_present() {
    let (app, _config, _pool) = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/config/export")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let disposition = response
        .headers()
        .get("content-disposition")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        disposition.contains("attachment"),
        "Content-Disposition must be attachment, got: {disposition}"
    );
    assert!(
        disposition.contains("ferrous-backup"),
        "Filename must contain ferrous-backup, got: {disposition}"
    );
}

// ── Testes de Import ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_import_valid_backup_returns_success_true() {
    let (app, _config, _pool) = create_test_app().await;
    let payload = serde_json::to_vec(&minimal_backup_json()).unwrap();

    let response = app.oneshot(import_request(&payload)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);
    assert!(json.get("summary").is_some());
}

#[tokio::test]
async fn test_import_new_local_record_is_added_to_config() {
    let (app, config, _pool) = create_test_app().await;

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([{
        "hostname": "printer",
        "domain": "home",
        "ip": "10.0.0.50",
        "record_type": "A",
        "ttl": 300
    }]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 1);
    assert_eq!(json["summary"]["local_records_skipped"], 0);

    let cfg = config.read().await;
    assert!(cfg
        .dns
        .local_records
        .iter()
        .any(|r| r.hostname == "printer"));
}

#[tokio::test]
async fn test_import_existing_local_record_is_skipped() {
    let (app, config, _pool) = create_test_app().await;

    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "server".to_string(),
            domain: Some("local".to_string()),
            ip: "10.0.0.1".to_string(),
            record_type: "A".to_string(),
            ttl: Some(300),
        });
    }

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([{
        "hostname": "server",
        "domain": "local",
        "ip": "10.0.0.1",
        "record_type": "A",
        "ttl": 300
    }]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 0);
    assert_eq!(json["summary"]["local_records_skipped"], 1);
}

#[tokio::test]
async fn test_import_is_idempotent() {
    let (_app, _config, pool) = create_test_app().await;

    let mut backup = minimal_backup_json();
    backup["data"]["groups"] = json!([{ "name": "Protected", "comment": null }]);

    let payload = serde_json::to_vec(&backup).unwrap();

    // Primeiro import
    let group_repo = Arc::new(SqliteGroupRepository::new(pool.clone()));
    let blocklist_source_repo = Arc::new(SqliteBlocklistSourceRepository::new(pool.clone()));
    let config = Arc::new(RwLock::new(Config::default()));

    let group_creator: Arc<dyn GroupCreator> = Arc::new(CreateGroupUseCase::new(
        group_repo.clone() as Arc<dyn ferrous_dns_application::ports::GroupRepository>,
    ));
    let blocklist_source_creator: Arc<dyn BlocklistSourceCreator> =
        Arc::new(CreateBlocklistSourceUseCase::new(
            blocklist_source_repo.clone()
                as Arc<dyn ferrous_dns_application::ports::BlocklistSourceRepository>,
            group_repo.clone() as Arc<dyn ferrous_dns_application::ports::GroupRepository>,
        ));
    let local_record_creator: Arc<dyn LocalRecordCreator> = Arc::new(
        CreateLocalRecordUseCase::new(config.clone(), Arc::new(NullConfigRepository)),
    );

    let import_uc = Arc::new(ImportConfigUseCase::new(
        config.clone(),
        Arc::new(NullConfigFilePersistence),
        Some("ferrous-dns.toml".to_string()),
        group_creator,
        blocklist_source_creator,
        local_record_creator,
    ));

    // Primeiro import — Protected já existe no DB, deve ser skipped
    let snapshot: ferrous_dns_application::use_cases::BackupSnapshot =
        serde_json::from_slice(&payload).unwrap();
    let summary1 = import_uc.execute(snapshot.clone()).await.unwrap();
    assert_eq!(summary1.groups_skipped, 1);
    assert_eq!(summary1.groups_imported, 0);

    // Segundo import — mesmo resultado
    let summary2 = import_uc.execute(snapshot).await.unwrap();
    assert_eq!(summary2.groups_skipped, 1);
    assert_eq!(summary2.groups_imported, 0);
}

#[tokio::test]
async fn test_import_new_group_is_created() {
    let (app, _config, _pool) = create_test_app().await;

    let mut backup = minimal_backup_json();
    backup["data"]["groups"] = json!([{ "name": "HomeDevices", "comment": "IoT group" }]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["groups_imported"], 1);
    assert_eq!(json["summary"]["groups_skipped"], 0);
}

#[tokio::test]
async fn test_import_without_file_returns_bad_request() {
    let (app, _config, _pool) = create_test_app().await;

    let boundary = "testboundary";
    let body = format!("--{boundary}--\r\n");

    let response = app
        .oneshot(
            Request::builder()
                .uri("/config/import")
                .method("POST")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_import_corrupt_json_returns_bad_request() {
    let (app, _config, _pool) = create_test_app().await;
    let response = app
        .oneshot(import_request(b"not valid json {{{"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_import_wrong_version_returns_error() {
    let (app, _config, _pool) = create_test_app().await;

    let mut backup = minimal_backup_json();
    backup["version"] = json!("99");

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();

    // Versão incompatível deve retornar erro (4xx ou 500)
    assert!(
        response.status().is_client_error() || response.status().is_server_error(),
        "Expected error status for incompatible version, got: {}",
        response.status()
    );
}

#[tokio::test]
async fn test_import_summary_errors_empty_on_success() {
    let (app, _config, _pool) = create_test_app().await;
    let payload = serde_json::to_vec(&minimal_backup_json()).unwrap();

    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(
        json["errors"].as_array().unwrap().len(),
        0,
        "errors must be empty on clean import"
    );
}

#[tokio::test]
async fn test_import_multiple_records_counted_correctly() {
    let (app, _config, _pool) = create_test_app().await;

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([
        { "hostname": "alpha", "domain": "lan", "ip": "10.0.0.1", "record_type": "A", "ttl": 300 },
        { "hostname": "beta",  "domain": "lan", "ip": "10.0.0.2", "record_type": "A", "ttl": 300 },
        { "hostname": "gamma", "domain": "lan", "ip": "10.0.0.3", "record_type": "A", "ttl": 300 },
    ]);
    backup["data"]["groups"] = json!([
        { "name": "Guests",  "comment": null },
        { "name": "Protected", "comment": null },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 3);
    assert_eq!(json["summary"]["local_records_skipped"], 0);
    assert_eq!(json["summary"]["groups_imported"], 1); // Guests é novo
    assert_eq!(json["summary"]["groups_skipped"], 1); // Protected já existe
}

// ── Cenários avançados: múltiplos records, sequências, overlap ────────────────

#[tokio::test]
async fn test_import_partial_overlap_counts_each_correctly() {
    let (app, config, _pool) = create_test_app().await;

    // Dois records já existem no config
    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "existing-a".to_string(),
            domain: Some("lan".to_string()),
            ip: "10.0.0.1".to_string(),
            record_type: "A".to_string(),
            ttl: Some(300),
        });
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "existing-b".to_string(),
            domain: Some("lan".to_string()),
            ip: "10.0.0.2".to_string(),
            record_type: "A".to_string(),
            ttl: Some(300),
        });
    }

    // Backup tem os 2 existentes + 3 novos
    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([
        { "hostname": "existing-a", "domain": "lan", "ip": "10.0.0.1", "record_type": "A", "ttl": 300 },
        { "hostname": "existing-b", "domain": "lan", "ip": "10.0.0.2", "record_type": "A", "ttl": 300 },
        { "hostname": "new-c",      "domain": "lan", "ip": "10.0.0.3", "record_type": "A", "ttl": 300 },
        { "hostname": "new-d",      "domain": "lan", "ip": "10.0.0.4", "record_type": "A", "ttl": 300 },
        { "hostname": "new-e",      "domain": "lan", "ip": "10.0.0.5", "record_type": "A", "ttl": 300 },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 3);
    assert_eq!(json["summary"]["local_records_skipped"], 2);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 5);
}

#[tokio::test]
async fn test_import_ipv6_aaaa_records() {
    let (app, config, _pool) = create_test_app().await;

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([
        { "hostname": "v6host",  "domain": "lan", "ip": "2001:db8::1", "record_type": "AAAA", "ttl": 300 },
        { "hostname": "v6host2", "domain": "lan", "ip": "2001:db8::2", "record_type": "AAAA", "ttl": null },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 2);

    let cfg = config.read().await;
    assert!(cfg
        .dns
        .local_records
        .iter()
        .any(|r| r.hostname == "v6host" && r.record_type == "AAAA"));
}

#[tokio::test]
async fn test_import_record_without_domain_is_distinct_from_record_with_domain() {
    let (app, config, _pool) = create_test_app().await;

    // Adiciona "server" sem domain
    {
        let mut cfg = config.write().await;
        cfg.dns.local_records.push(LocalDnsRecord {
            hostname: "server".to_string(),
            domain: None,
            ip: "10.0.0.1".to_string(),
            record_type: "A".to_string(),
            ttl: Some(300),
        });
    }

    // Importa "server" com domain "lan" — deve ser tratado como distinto
    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([
        { "hostname": "server", "domain": "lan", "ip": "10.0.0.1", "record_type": "A", "ttl": 300 },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 1);
    assert_eq!(json["summary"]["local_records_skipped"], 0);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 2);
}

#[tokio::test]
async fn test_import_same_hostname_different_domain_are_distinct_records() {
    let (app, config, _pool) = create_test_app().await;

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!([
        { "hostname": "pi", "domain": "home",   "ip": "192.168.1.10", "record_type": "A", "ttl": 300 },
        { "hostname": "pi", "domain": "office", "ip": "10.0.0.10",    "record_type": "A", "ttl": 300 },
        { "hostname": "pi", "domain": "lab",    "ip": "172.16.0.10",  "record_type": "A", "ttl": 300 },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 3);

    let cfg = config.read().await;
    assert_eq!(
        cfg.dns
            .local_records
            .iter()
            .filter(|r| r.hostname == "pi")
            .count(),
        3
    );
}

#[tokio::test]
async fn test_sequential_imports_accumulate_distinct_records() {
    let (app, config, _pool) = create_test_app().await;

    // Primeiro import: 3 records
    let mut backup1 = minimal_backup_json();
    backup1["data"]["local_records"] = json!([
        { "hostname": "alpha", "domain": "lan", "ip": "10.0.0.1", "record_type": "A", "ttl": 300 },
        { "hostname": "beta",  "domain": "lan", "ip": "10.0.0.2", "record_type": "A", "ttl": 300 },
        { "hostname": "gamma", "domain": "lan", "ip": "10.0.0.3", "record_type": "A", "ttl": 300 },
    ]);

    let r1 = app
        .clone()
        .oneshot(import_request(&serde_json::to_vec(&backup1).unwrap()))
        .await
        .unwrap();
    let b1: Value =
        serde_json::from_slice(&r1.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(b1["summary"]["local_records_imported"], 3);
    assert_eq!(b1["summary"]["local_records_skipped"], 0);

    // Segundo import: 2 novos + 1 existente (gamma)
    let mut backup2 = minimal_backup_json();
    backup2["data"]["local_records"] = json!([
        { "hostname": "gamma", "domain": "lan", "ip": "10.0.0.3", "record_type": "A", "ttl": 300 },
        { "hostname": "delta", "domain": "lan", "ip": "10.0.0.4", "record_type": "A", "ttl": 300 },
        { "hostname": "epsilon","domain": "lan", "ip": "10.0.0.5", "record_type": "A", "ttl": 300 },
    ]);

    let r2 = app
        .oneshot(import_request(&serde_json::to_vec(&backup2).unwrap()))
        .await
        .unwrap();
    let b2: Value =
        serde_json::from_slice(&r2.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(b2["summary"]["local_records_imported"], 2);
    assert_eq!(b2["summary"]["local_records_skipped"], 1);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 5);
}

#[tokio::test]
async fn test_import_large_batch_of_records() {
    let (app, config, _pool) = create_test_app().await;

    let records: Vec<Value> = (1..=20)
        .map(|i| {
            json!({
                "hostname": format!("host-{i:02}"),
                "domain": "corp",
                "ip": format!("10.1.0.{i}"),
                "record_type": "A",
                "ttl": 300
            })
        })
        .collect();

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!(records);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 20);
    assert_eq!(json["summary"]["local_records_skipped"], 0);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 20);
}

#[tokio::test]
async fn test_import_large_batch_second_run_skips_all() {
    let (app, config, _pool) = create_test_app().await;

    let records: Vec<Value> = (1..=10)
        .map(|i| {
            json!({
                "hostname": format!("srv-{i:02}"),
                "domain": "prod",
                "ip": format!("172.16.0.{i}"),
                "record_type": "A",
                "ttl": 60
            })
        })
        .collect();

    let mut backup = minimal_backup_json();
    backup["data"]["local_records"] = json!(records);
    let payload = serde_json::to_vec(&backup).unwrap();

    // Primeiro import
    app.clone().oneshot(import_request(&payload)).await.unwrap();

    assert_eq!(config.read().await.dns.local_records.len(), 10);

    // Segundo import — tudo já existe
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 0);
    assert_eq!(json["summary"]["local_records_skipped"], 10);

    // Config não cresceu
    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 10);
}

#[tokio::test]
async fn test_export_then_import_is_a_complete_round_trip() {
    let (app, config, _pool) = create_test_app().await;

    // Popula config com records e verifica que o export captura tudo
    {
        let mut cfg = config.write().await;
        for i in 1..=5 {
            cfg.dns.local_records.push(LocalDnsRecord {
                hostname: format!("node-{i}"),
                domain: Some("cluster".to_string()),
                ip: format!("192.168.10.{i}"),
                record_type: "A".to_string(),
                ttl: Some(120),
            });
        }
    }

    // Export
    let export_response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/config/export")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(export_response.status(), StatusCode::OK);
    let export_bytes = export_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let export_json: Value = serde_json::from_slice(&export_bytes).unwrap();

    // Valida o export
    let exported_records = export_json["data"]["local_records"].as_array().unwrap();
    assert_eq!(exported_records.len(), 5);
    assert!(exported_records.iter().any(|r| r["hostname"] == "node-1"));
    assert!(exported_records.iter().any(|r| r["hostname"] == "node-5"));

    // Import do arquivo exportado — tudo já existe, deve skipar
    let import_response = app.oneshot(import_request(&export_bytes)).await.unwrap();

    let body = import_response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let import_json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(import_json["success"], true);
    assert_eq!(import_json["summary"]["local_records_imported"], 0);
    assert_eq!(import_json["summary"]["local_records_skipped"], 5);

    // Config não duplicou
    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 5);
}

#[tokio::test]
async fn test_import_mixed_ipv4_and_ipv6_records() {
    let (app, config, _pool) = create_test_app().await;

    let mut backup = minimal_backup_json();
    // Each hostname is unique — the duplicate key is hostname+domain, not record_type,
    // so all four records must be imported independently.
    backup["data"]["local_records"] = json!([
        { "hostname": "srv-v4a", "domain": "lan", "ip": "10.0.0.1",    "record_type": "A",    "ttl": 300 },
        { "hostname": "srv-v6a", "domain": "lan", "ip": "::1",          "record_type": "AAAA", "ttl": 300 },
        { "hostname": "srv-v4b", "domain": "lan", "ip": "10.0.0.2",    "record_type": "A",    "ttl": 300 },
        { "hostname": "srv-v6b", "domain": "lan", "ip": "2001:db8::1", "record_type": "AAAA", "ttl": 300 },
    ]);

    let payload = serde_json::to_vec(&backup).unwrap();
    let response = app.oneshot(import_request(&payload)).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["success"], true);
    assert_eq!(json["summary"]["local_records_imported"], 4);
    assert_eq!(json["summary"]["local_records_skipped"], 0);

    let cfg = config.read().await;
    assert_eq!(cfg.dns.local_records.len(), 4);
    let a_count = cfg
        .dns
        .local_records
        .iter()
        .filter(|r| r.record_type == "A")
        .count();
    let aaaa_count = cfg
        .dns
        .local_records
        .iter()
        .filter(|r| r.record_type == "AAAA")
        .count();
    assert_eq!(a_count, 2);
    assert_eq!(aaaa_count, 2);
}
