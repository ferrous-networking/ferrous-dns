use super::stubs::{
    NullBlockFilterEngine, NullBlockedServiceRepository, NullConfigFilePersistence,
    NullConfigRepository, NullCustomServiceRepository, NullSafeSearchConfigRepository,
    NullSafeSearchEnginePort, NullScheduleProfileRepository, NullServiceCatalog,
};
use super::{build_test_auth_use_cases, build_test_backup_use_cases, MockTlsCertificateService};
use axum::Router;
use ferrous_dns_api::{
    create_api_router_with_openapi, AppState, BackupUseCases, BlockingUseCases, ClientUseCases,
    DnsUseCases, GroupUseCases, QueryUseCases, SafeSearchUseCases, ScheduleUseCases,
    ServiceUseCases,
};
use ferrous_dns_application::drop_counter::ShedCounters;
use ferrous_dns_application::ports::{
    BlockFilterEnginePort, DnsCachePort, SafeSearchConfigRepository, SafeSearchEnginePort,
    UpstreamReloadPort,
};
use ferrous_dns_application::use_cases::*;
use ferrous_dns_domain::config::upstream::{UpstreamPool, UpstreamStrategy};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::Config;
use ferrous_dns_infrastructure::dns::cache::DnsCache;
use ferrous_dns_infrastructure::dns::dnssec::DnssecStatsAdapter;
use ferrous_dns_infrastructure::dns::{
    DnsCacheConfig, EvictionStrategy, PoolManager, UpstreamHealthAdapter, UpstreamReloadAdapter,
};
use ferrous_dns_infrastructure::repositories::blocklist_repository::SqliteBlocklistRepository;
use ferrous_dns_infrastructure::repositories::blocklist_source_repository::SqliteBlocklistSourceRepository;
use ferrous_dns_infrastructure::repositories::client_repository::SqliteClientRepository;
use ferrous_dns_infrastructure::repositories::client_subnet_repository::SqliteClientSubnetRepository;
use ferrous_dns_infrastructure::repositories::group_repository::SqliteGroupRepository;
use ferrous_dns_infrastructure::repositories::managed_domain_repository::SqliteManagedDomainRepository;
use ferrous_dns_infrastructure::repositories::query_log_repository::SqliteQueryLogRepository;
use ferrous_dns_infrastructure::repositories::regex_filter_repository::SqliteRegexFilterRepository;
use ferrous_dns_infrastructure::repositories::sqlite_safe_search_config_repository::SqliteSafeSearchConfigRepository;
use ferrous_dns_infrastructure::repositories::whitelist_repository::SqliteWhitelistRepository;
use ferrous_dns_infrastructure::repositories::whitelist_source_repository::SqliteWhitelistSourceRepository;
use ferrous_dns_infrastructure::repositories::TomlConfigFilePersistence;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::RwLock;

/// In-memory SQLite with the production schema; only the default `Protected` group (id 1) exists.
pub async fn create_test_db() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .unwrap();
    sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
    pool
}

/// A fully wired API router plus the handles tests use to seed or inspect state.
pub struct TestApp {
    pub router: Router,
    pub state: AppState,
    pub pool: SqlitePool,
    pub config: Arc<RwLock<Config>>,
    pub cache: Arc<DnsCache>,
    pub client_repo: Arc<SqliteClientRepository>,
    pub pool_manager: Arc<PoolManager>,
    pub query_log: Arc<SqliteQueryLogRepository>,
}

impl TestApp {
    pub async fn new() -> Self {
        Self::builder().build().await
    }

    pub fn builder() -> TestAppBuilder {
        TestAppBuilder::default()
    }
}

#[derive(Default)]
pub struct TestAppBuilder {
    pool: Option<SqlitePool>,
    groups: Vec<String>,
    sync_engine: Option<Arc<dyn BlockFilterEnginePort>>,
    cache_max_entries: usize,
    config_path: Option<Arc<str>>,
    sqlite_safe_search: bool,
    sqlite_backup: bool,
    overrides: ConfigOverrides,
    query_log_channel_capacity: Option<usize>,
}

impl TestAppBuilder {
    /// Uses an existing pool (e.g. pre-seeded) instead of a fresh `create_test_db()`.
    pub fn pool(mut self, pool: SqlitePool) -> Self {
        self.pool = Some(pool);
        self
    }

    /// Inserts extra groups after `Protected`, with ids 2, 3, … in the given order.
    pub fn groups(mut self, names: &[&str]) -> Self {
        self.groups = names.iter().map(|name| name.to_string()).collect();
        self
    }

    /// Engine used by the blocklist-sources sync use case only.
    pub fn sync_engine(mut self, engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        self.sync_engine = Some(engine);
        self
    }

    pub fn cache_max_entries(mut self, max_entries: usize) -> Self {
        self.cache_max_entries = max_entries;
        self
    }

    pub fn config_path(mut self, path: &str) -> Self {
        self.config_path = Some(Arc::from(path));
        self
    }

    /// Backs the safe-search use cases with the SQLite repository instead of a null stub.
    pub fn sqlite_safe_search(mut self) -> Self {
        self.sqlite_safe_search = true;
        self
    }

    /// Backs export/import with the SQLite group and blocklist-source repositories.
    pub fn sqlite_backup(mut self) -> Self {
        self.sqlite_backup = true;
        self
    }

    /// Command-line overrides the reload use case re-applies.
    pub fn overrides(mut self, overrides: ConfigOverrides) -> Self {
        self.overrides = overrides;
        self
    }

    /// Query log batching channel capacity, in place of the production default.
    pub fn query_log_channel_capacity(mut self, capacity: usize) -> Self {
        self.query_log_channel_capacity = Some(capacity);
        self
    }

    pub async fn build(self) -> TestApp {
        let pool = match self.pool {
            Some(pool) => pool,
            None => create_test_db().await,
        };
        for (id, name) in (2_i64..).zip(&self.groups) {
            sqlx::query("INSERT INTO groups (id, name) VALUES (?, ?)")
                .bind(id)
                .bind(name)
                .execute(&pool)
                .await
                .unwrap();
        }

        let mut db_config = DatabaseConfig::default();
        if let Some(capacity) = self.query_log_channel_capacity {
            db_config.query_log_channel_capacity = capacity;
        }
        let shed = ShedCounters::default();
        let client_repo = Arc::new(SqliteClientRepository::new(pool.clone(), &db_config));
        let group_repo = Arc::new(SqliteGroupRepository::new(pool.clone()));
        let subnet_repo = Arc::new(SqliteClientSubnetRepository::new(pool.clone()));
        let blocklist_source_repo = Arc::new(SqliteBlocklistSourceRepository::new(pool.clone()));
        let whitelist_source_repo = Arc::new(SqliteWhitelistSourceRepository::new(pool.clone()));
        let managed_domain_repo = Arc::new(SqliteManagedDomainRepository::new(pool.clone()));
        let regex_filter_repo = Arc::new(SqliteRegexFilterRepository::new(pool.clone()));
        let query_log_repo = Arc::new(SqliteQueryLogRepository::new(
            pool.clone(),
            pool.clone(),
            pool.clone(),
            &db_config,
            shed.query_log.clone(),
        ));
        let null_engine: Arc<dyn BlockFilterEnginePort> = Arc::new(NullBlockFilterEngine);
        let sync_engine = self.sync_engine.unwrap_or_else(|| null_engine.clone());
        let safe_search_repo: Arc<dyn SafeSearchConfigRepository> = if self.sqlite_safe_search {
            Arc::new(SqliteSafeSearchConfigRepository::new(pool.clone()))
        } else {
            Arc::new(NullSafeSearchConfigRepository)
        };
        let safe_search_engine: Arc<dyn SafeSearchEnginePort> = Arc::new(NullSafeSearchEnginePort);

        let config = Arc::new(RwLock::new(Config::builtin()));
        let cache = Arc::new(DnsCache::new(DnsCacheConfig {
            max_entries: self.cache_max_entries,
            eviction_strategy: EvictionStrategy::LRU,
            refresh_threshold: 0.0,
            batch_eviction_percentage: 0.0,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 7200,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
            min_ttl: 0,
            max_ttl: 86_400,
        }));
        let upstream = UpstreamPool {
            name: "test".to_string(),
            strategy: UpstreamStrategy::Parallel,
            priority: 1,
            servers: vec!["8.8.8.8:53".to_string()],
            weight: None,
        };
        let pool_manager = Arc::new(
            PoolManager::new(vec![upstream], None)
                .await
                .expect("Failed to create PoolManager"),
        );

        let config_writer: Arc<tokio::sync::Mutex<()>> = Arc::default();
        let backup = if self.sqlite_backup {
            sqlite_backup_use_cases(&config, &config_writer, &group_repo, &blocklist_source_repo)
        } else {
            build_test_backup_use_cases(config.clone(), config_writer.clone())
        };
        let reload_upstream: Arc<dyn UpstreamReloadPort> =
            Arc::new(UpstreamReloadAdapter::new(vec![
                pool_manager.clone(),
                pool_manager.clone(),
            ]));
        let reload_config = self.config_path.clone().map(|path| {
            Arc::new(ReloadConfigUseCase::new(
                config.clone(),
                config_writer.clone(),
                Arc::new(TomlConfigFilePersistence),
                path,
                reload_upstream.clone(),
                self.overrides.clone(),
            ))
        });

        let state = AppState {
            query: QueryUseCases {
                get_stats: Arc::new(GetQueryStatsUseCase::new(
                    query_log_repo.clone(),
                    client_repo.clone(),
                )),
                get_queries: Arc::new(GetRecentQueriesUseCase::new(query_log_repo.clone())),
                get_timeline: Arc::new(GetTimelineUseCase::new(query_log_repo.clone())),
                get_query_rate: Arc::new(GetQueryRateUseCase::new(query_log_repo.clone())),
                get_cache_stats: Arc::new(GetCacheStatsUseCase::new(query_log_repo.clone())),
                get_top_blocked_domains: Arc::new(GetTopBlockedDomainsUseCase::new(
                    query_log_repo.clone(),
                )),
                get_top_clients: Arc::new(GetTopClientsUseCase::new(query_log_repo.clone())),
            },
            dns: DnsUseCases {
                cache: cache.clone() as Arc<dyn DnsCachePort>,
                create_local_record: Arc::new(CreateLocalRecordUseCase::new(
                    config.clone(),
                    Arc::new(NullConfigRepository),
                )),
                update_local_record: Arc::new(UpdateLocalRecordUseCase::new(
                    config.clone(),
                    Arc::new(NullConfigRepository),
                )),
                delete_local_record: Arc::new(DeleteLocalRecordUseCase::new(
                    config.clone(),
                    Arc::new(NullConfigRepository),
                )),
                dnssec_stats: Arc::new(DnssecStatsAdapter::disabled()),
                shed,
                upstream_health: Arc::new(UpstreamHealthAdapter::new(pool_manager.clone(), None)),
                reload_upstream,
            },
            groups: GroupUseCases {
                get_groups: Arc::new(GetGroupsUseCase::new(group_repo.clone())),
                create_group: Arc::new(CreateGroupUseCase::new(group_repo.clone())),
                update_group: Arc::new(UpdateGroupUseCase::new(group_repo.clone())),
                delete_group: Arc::new(DeleteGroupUseCase::new(
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                assign_client_group: Arc::new(AssignClientGroupUseCase::new(
                    client_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
            },
            clients: ClientUseCases {
                get_clients: Arc::new(GetClientsUseCase::new(client_repo.clone())),
                create_manual_client: Arc::new(CreateManualClientUseCase::new(
                    client_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                update_client: Arc::new(UpdateClientUseCase::new(
                    client_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                delete_client: Arc::new(DeleteClientUseCase::new(
                    client_repo.clone(),
                    null_engine.clone(),
                )),
                get_client_subnets: Arc::new(GetClientSubnetsUseCase::new(subnet_repo.clone())),
                create_client_subnet: Arc::new(CreateClientSubnetUseCase::new(
                    subnet_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                delete_client_subnet: Arc::new(DeleteClientSubnetUseCase::new(
                    subnet_repo.clone(),
                    null_engine.clone(),
                )),
            },
            blocking: BlockingUseCases {
                get_blocklist: Arc::new(GetBlocklistUseCase::new(Arc::new(
                    SqliteBlocklistRepository::new(pool.clone()),
                ))),
                get_blocklist_sources: Arc::new(GetBlocklistSourcesUseCase::new(
                    blocklist_source_repo.clone(),
                )),
                create_blocklist_source: Arc::new(CreateBlocklistSourceUseCase::new(
                    blocklist_source_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                update_blocklist_source: Arc::new(UpdateBlocklistSourceUseCase::new(
                    blocklist_source_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                delete_blocklist_source: Arc::new(DeleteBlocklistSourceUseCase::new(
                    blocklist_source_repo.clone(),
                    null_engine.clone(),
                )),
                sync_blocklist_sources: Arc::new(SyncBlocklistSourcesUseCase::new(sync_engine)),
                get_whitelist: Arc::new(GetWhitelistUseCase::new(Arc::new(
                    SqliteWhitelistRepository::new(pool.clone()),
                ))),
                get_whitelist_sources: Arc::new(GetWhitelistSourcesUseCase::new(
                    whitelist_source_repo.clone(),
                )),
                create_whitelist_source: Arc::new(CreateWhitelistSourceUseCase::new(
                    whitelist_source_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                update_whitelist_source: Arc::new(UpdateWhitelistSourceUseCase::new(
                    whitelist_source_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                delete_whitelist_source: Arc::new(DeleteWhitelistSourceUseCase::new(
                    whitelist_source_repo.clone(),
                    null_engine.clone(),
                )),
                get_managed_domains: Arc::new(GetManagedDomainsUseCase::new(
                    managed_domain_repo.clone(),
                )),
                create_managed_domain: Arc::new(CreateManagedDomainUseCase::new(
                    managed_domain_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                update_managed_domain: Arc::new(UpdateManagedDomainUseCase::new(
                    managed_domain_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                delete_managed_domain: Arc::new(DeleteManagedDomainUseCase::new(
                    managed_domain_repo.clone(),
                    null_engine.clone(),
                )),
                get_regex_filters: Arc::new(GetRegexFiltersUseCase::new(regex_filter_repo.clone())),
                create_regex_filter: Arc::new(CreateRegexFilterUseCase::new(
                    regex_filter_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                update_regex_filter: Arc::new(UpdateRegexFilterUseCase::new(
                    regex_filter_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                )),
                delete_regex_filter: Arc::new(DeleteRegexFilterUseCase::new(
                    regex_filter_repo.clone(),
                    null_engine.clone(),
                )),
                get_block_filter_stats: Arc::new(GetBlockFilterStatsUseCase::new(
                    null_engine.clone(),
                )),
                test_domain: Arc::new(TestDomainUseCase::new(null_engine.clone())),
                backtest: Arc::new(BacktestBlocklistsUseCase::new(
                    null_engine.clone(),
                    query_log_repo.clone(),
                )),
            },
            services: ServiceUseCases {
                get_service_catalog: Arc::new(GetServiceCatalogUseCase::new(Arc::new(
                    NullServiceCatalog,
                ))),
                get_blocked_services: Arc::new(GetBlockedServicesUseCase::new(Arc::new(
                    NullBlockedServiceRepository,
                ))),
                block_service: Arc::new(BlockServiceUseCase::new(
                    Arc::new(NullBlockedServiceRepository),
                    managed_domain_repo.clone(),
                    group_repo.clone(),
                    null_engine.clone(),
                    Arc::new(NullServiceCatalog),
                )),
                unblock_service: Arc::new(UnblockServiceUseCase::new(
                    Arc::new(NullBlockedServiceRepository),
                    managed_domain_repo.clone(),
                    null_engine.clone(),
                )),
                create_custom_service: Arc::new(CreateCustomServiceUseCase::new(
                    Arc::new(NullCustomServiceRepository),
                    Arc::new(NullServiceCatalog),
                )),
                get_custom_services: Arc::new(GetCustomServicesUseCase::new(Arc::new(
                    NullCustomServiceRepository,
                ))),
                update_custom_service: Arc::new(UpdateCustomServiceUseCase::new(
                    Arc::new(NullCustomServiceRepository),
                    Arc::new(NullServiceCatalog),
                    managed_domain_repo.clone(),
                    Arc::new(NullBlockedServiceRepository),
                    null_engine.clone(),
                )),
                delete_custom_service: Arc::new(DeleteCustomServiceUseCase::new(
                    Arc::new(NullCustomServiceRepository),
                    Arc::new(NullServiceCatalog),
                    Arc::new(NullBlockedServiceRepository),
                    managed_domain_repo.clone(),
                    null_engine.clone(),
                )),
            },
            safe_search: SafeSearchUseCases {
                get_configs: Arc::new(GetSafeSearchConfigsUseCase::new(
                    safe_search_repo.clone(),
                    group_repo.clone(),
                )),
                toggle: Arc::new(ToggleSafeSearchUseCase::new(
                    safe_search_repo.clone(),
                    group_repo.clone(),
                    safe_search_engine.clone(),
                )),
                delete_configs: Arc::new(DeleteSafeSearchConfigsUseCase::new(
                    safe_search_repo,
                    group_repo.clone(),
                    safe_search_engine,
                )),
            },
            schedule: ScheduleUseCases {
                get_profiles: Arc::new(GetScheduleProfilesUseCase::new(Arc::new(
                    NullScheduleProfileRepository,
                ))),
                create_profile: Arc::new(CreateScheduleProfileUseCase::new(Arc::new(
                    NullScheduleProfileRepository,
                ))),
                update_profile: Arc::new(UpdateScheduleProfileUseCase::new(Arc::new(
                    NullScheduleProfileRepository,
                ))),
                delete_profile: Arc::new(DeleteScheduleProfileUseCase::new(Arc::new(
                    NullScheduleProfileRepository,
                ))),
                manage_slots: Arc::new(ManageTimeSlotsUseCase::new(Arc::new(
                    NullScheduleProfileRepository,
                ))),
                assign_profile: Arc::new(AssignScheduleProfileUseCase::new(
                    Arc::new(NullScheduleProfileRepository),
                    group_repo.clone(),
                )),
            },
            auth: build_test_auth_use_cases(),
            backup,
            config: config.clone(),
            config_writer,
            config_file_persistence: Arc::new(TomlConfigFilePersistence),
            config_path: self.config_path,
            reload_config,
            tls_cert: Arc::new(MockTlsCertificateService),
            webauthn_configured: false,
            tls_enabled: false,
            restart_pending: Default::default(),
        };

        TestApp {
            router: create_api_router_with_openapi(state.clone()).0,
            state,
            pool,
            config,
            cache,
            client_repo,
            pool_manager,
            query_log: query_log_repo,
        }
    }
}

fn sqlite_backup_use_cases(
    config: &Arc<RwLock<Config>>,
    config_writer: &Arc<tokio::sync::Mutex<()>>,
    group_repo: &Arc<SqliteGroupRepository>,
    blocklist_source_repo: &Arc<SqliteBlocklistSourceRepository>,
) -> BackupUseCases {
    let null_engine: Arc<dyn BlockFilterEnginePort> = Arc::new(NullBlockFilterEngine);
    BackupUseCases {
        export: Arc::new(ExportConfigUseCase::new(
            config.clone(),
            group_repo.clone(),
            blocklist_source_repo.clone(),
        )),
        import: Arc::new(ImportConfigUseCase::new(
            ConfigDestination {
                config: config.clone(),
                writer: config_writer.clone(),
                persistence: Arc::new(NullConfigFilePersistence),
                path: Some("ferrous-dns.toml".to_string()),
            },
            Arc::new(CreateGroupUseCase::new(group_repo.clone())),
            Arc::new(CreateBlocklistSourceUseCase::new(
                blocklist_source_repo.clone(),
                group_repo.clone(),
                null_engine.clone(),
            )),
            Arc::new(CreateLocalRecordUseCase::new(
                config.clone(),
                Arc::new(NullConfigRepository),
            )),
            null_engine.clone(),
        )),
    }
}
