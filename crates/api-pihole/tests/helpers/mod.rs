#![allow(dead_code)]

pub mod auth;
pub mod ftl;

use async_trait::async_trait;
use axum::Router;
use ferrous_dns_api_pihole::state::{
    PiholeBlockingState, PiholeClientState, PiholeGroupState, PiholeListsState, PiholeQueryState,
    PiholeSystemState,
};
use ferrous_dns_api_pihole::{create_pihole_router_with_openapi, PiholeAppState};
use ferrous_dns_application::ports::{
    BlockFilterEnginePort, CacheEntryPage, CacheEntryQuery, CacheMetricsSnapshot, CacheOverview,
    DnsCachePort, FilterDecision,
};
use ferrous_dns_application::use_cases::{
    CleanupOldQueryLogsUseCase, CreateBlocklistSourceUseCase, CreateClientSubnetUseCase,
    CreateGroupUseCase, CreateManagedDomainUseCase, CreateManualClientUseCase,
    CreateRegexFilterUseCase, CreateWhitelistSourceUseCase, DeleteBlocklistSourceUseCase,
    DeleteClientSubnetUseCase, DeleteClientUseCase, DeleteGroupUseCase, DeleteManagedDomainUseCase,
    DeleteRegexFilterUseCase, DeleteWhitelistSourceUseCase, GetBlocklistSourcesUseCase,
    GetClientActivityUseCase, GetClientSubnetsUseCase, GetClientsUseCase, GetGroupsUseCase,
    GetManagedDomainsUseCase, GetQueryLogStorageUseCase, GetQueryRateUseCase, GetQueryStatsUseCase,
    GetRecentQueriesUseCase, GetRegexFiltersUseCase, GetTimelineUseCase,
    GetTopAllowedDomainsUseCase, GetTopBlockedClientsUseCase, GetTopBlockedDomainsUseCase,
    GetTopClientsUseCase, GetUniqueDomainsUseCase, GetWhitelistSourcesUseCase,
    SetClientCommentUseCase, UpdateBlocklistSourceUseCase, UpdateClientSubnetUseCase,
    UpdateClientUseCase, UpdateGroupUseCase, UpdateManagedDomainUseCase, UpdateRegexFilterUseCase,
    UpdateWhitelistSourceUseCase,
};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::{
    AllowMatch, AllowMatchKind, BlockMatch, BlockMatchKind, BlockSource, Config, DomainError,
    FilterExplanation, MatchType,
};
use ferrous_dns_infrastructure::repositories::{
    blocklist_source_repository::SqliteBlocklistSourceRepository,
    client_repository::SqliteClientRepository,
    client_subnet_repository::SqliteClientSubnetRepository,
    group_repository::SqliteGroupRepository,
    managed_domain_repository::SqliteManagedDomainRepository,
    query_log_repository::SqliteQueryLogRepository,
    regex_filter_repository::SqliteRegexFilterRepository,
    whitelist_source_repository::SqliteWhitelistSourceRepository,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Client IP the mock engine resolves to [`MOCK_CLIENT_GROUP`]; every other
/// client resolves to the default group 1.
pub const MOCK_GROUPED_CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
pub const MOCK_CLIENT_GROUP: i64 = 2;

/// Database ids the mock engine's `explain` attributes its matches to. A
/// test that creates the rows in order on a fresh database gets these ids.
pub const MOCK_BLOCKLIST_ID: i64 = 1;
pub const MOCK_GROUP_BLOCKLIST_ID: i64 = 2;
pub const MOCK_DENY_REGEX_ID: i64 = 1;
pub const MOCK_ALLOW_REGEX_ID: i64 = 2;
/// The first allowlist created gets this id.
pub const MOCK_ALLOWLIST_ID: i64 = 1;

/// How long before the app was built the test process "started", so uptimes
/// are large enough to tell seconds from milliseconds.
pub const PROCESS_AGE: std::time::Duration = std::time::Duration::from_secs(5);

/// What the stub DNS cache reports: insertions, evictions, and expired
/// entries removed on access.
pub const STUB_CACHE_INSERTIONS: u64 = 42;
pub const STUB_CACHE_EVICTIONS: u64 = 7;
pub const STUB_CACHE_EXPIRED: u64 = 3;

/// A cache that holds nothing and reports the `STUB_CACHE_*` counters.
struct StubDnsCache;

impl DnsCachePort for StubDnsCache {
    fn cache_size(&self) -> usize {
        0
    }

    fn cache_metrics_snapshot(&self) -> CacheMetricsSnapshot {
        CacheMetricsSnapshot {
            insertions: STUB_CACHE_INSERTIONS,
            evictions: STUB_CACHE_EVICTIONS,
            lazy_deletions: STUB_CACHE_EXPIRED,
            ..CacheMetricsSnapshot::default()
        }
    }

    fn insert_permanent_record(
        &self,
        _domain: &str,
        _record_type: ferrous_dns_domain::RecordType,
        _addresses: Vec<IpAddr>,
        _ttl: u32,
    ) {
    }

    fn remove_record(
        &self,
        _domain: &str,
        _record_type: &ferrous_dns_domain::RecordType,
        _group_id: Option<i64>,
    ) -> bool {
        false
    }

    fn is_permanent_record(
        &self,
        _domain: &str,
        _record_type: &ferrous_dns_domain::RecordType,
    ) -> bool {
        false
    }

    fn list_entries(&self, _query: &CacheEntryQuery) -> CacheEntryPage {
        CacheEntryPage {
            entries: Vec::new(),
            total: 0,
            records_total: 0,
        }
    }

    fn cache_overview(&self, _top: usize, _expiring_within_secs: u64) -> CacheOverview {
        CacheOverview::default()
    }
}

/// Domain decisions of the mock engine:
/// - `regex.blocked.test` → blocked by the deny regex [`MOCK_DENY_REGEX_ID`]
/// - `list.blocked.test` → blocked by the blocklist [`MOCK_BLOCKLIST_ID`]
///   and by the manual blocklist, which has no id
/// - `allowlisted.test` → explicitly allowed by the allowlist
///   [`MOCK_ALLOWLIST_ID`], by the manual allowlist, which has no id, and by
///   the allow regex [`MOCK_ALLOW_REGEX_ID`]
/// - `group.blocked.test` → blocked by the blocklist
///   [`MOCK_GROUP_BLOCKLIST_ID`] in [`MOCK_CLIENT_GROUP`] only
/// - anything else → allowed
struct MockBlockFilterEngine {
    blocking_enabled: AtomicBool,
}

#[async_trait]
impl BlockFilterEnginePort for MockBlockFilterEngine {
    fn resolve_group(&self, ip: IpAddr) -> i64 {
        if ip == MOCK_GROUPED_CLIENT {
            MOCK_CLIENT_GROUP
        } else {
            1
        }
    }

    fn check(&self, domain: &str, group_id: i64) -> FilterDecision {
        match domain {
            "regex.blocked.test" => FilterDecision::Block(BlockSource::RegexFilter),
            "list.blocked.test" => FilterDecision::Block(BlockSource::Blocklist),
            "allowlisted.test" => FilterDecision::ExplicitAllow,
            "group.blocked.test" if group_id == MOCK_CLIENT_GROUP => {
                FilterDecision::Block(BlockSource::Blocklist)
            }
            _ => FilterDecision::Allow,
        }
    }

    fn explain(&self, domain: &str, group_id: i64) -> FilterExplanation {
        let block = |kind, source_id, match_type| BlockMatch {
            kind,
            source_id,
            name: String::new(),
            match_type,
        };
        let allow = |kind, source_id, match_type| AllowMatch {
            kind,
            source_id,
            name: String::new(),
            match_type,
        };
        let (allow_reasons, block_matches) = match domain {
            "regex.blocked.test" => (
                vec![],
                vec![block(
                    BlockMatchKind::Regex,
                    Some(MOCK_DENY_REGEX_ID),
                    MatchType::Regex,
                )],
            ),
            "list.blocked.test" => (
                vec![],
                vec![
                    block(
                        BlockMatchKind::Blocklist,
                        Some(MOCK_BLOCKLIST_ID),
                        MatchType::Exact,
                    ),
                    block(BlockMatchKind::Manual, None, MatchType::Exact),
                ],
            ),
            "allowlisted.test" => (
                vec![
                    allow(
                        AllowMatchKind::Allowlist,
                        Some(MOCK_ALLOWLIST_ID),
                        MatchType::Exact,
                    ),
                    allow(AllowMatchKind::Allowlist, None, MatchType::Exact),
                    allow(
                        AllowMatchKind::Regex,
                        Some(MOCK_ALLOW_REGEX_ID),
                        MatchType::Regex,
                    ),
                ],
                vec![],
            ),
            "group.blocked.test" if group_id == MOCK_CLIENT_GROUP => (
                vec![],
                vec![block(
                    BlockMatchKind::Blocklist,
                    Some(MOCK_GROUP_BLOCKLIST_ID),
                    MatchType::Wildcard,
                )],
            ),
            _ => (vec![], vec![]),
        };
        FilterExplanation {
            domain: domain.to_string(),
            group_id,
            blocked: allow_reasons.is_empty() && !block_matches.is_empty(),
            allow_reasons,
            block_matches,
        }
    }
    fn match_candidate(
        &self,
        _domains: &[String],
        _list_lines: &[String],
        _regexes: &[String],
    ) -> Result<Vec<bool>, DomainError> {
        unimplemented!()
    }
    fn store_cname_decision(&self, _domain: &str, _group_id: i64, _ttl_secs: u64) {}

    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }

    async fn load_client_groups(&self) -> Result<(), DomainError> {
        Ok(())
    }

    fn compiled_domain_count(&self) -> usize {
        0
    }

    fn is_blocking_enabled(&self) -> bool {
        self.blocking_enabled.load(Ordering::Relaxed)
    }

    fn set_blocking_enabled(&self, enabled: bool) {
        self.blocking_enabled.store(enabled, Ordering::Relaxed);
    }
}

pub async fn create_test_db() -> sqlx::SqlitePool {
    let pool = SqlitePoolOptions::new()
        .connect("sqlite::memory:")
        .await
        .expect("Failed to create in-memory SQLite pool");

    sqlx::query(
        "CREATE TABLE groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            enabled BOOLEAN NOT NULL DEFAULT 1,
            comment TEXT,
            is_default BOOLEAN NOT NULL DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create groups table");

    sqlx::query(
        "INSERT INTO groups (id, name, enabled, comment, is_default)
         VALUES (1, 'Protected', 1, 'Default group', 1)",
    )
    .execute(&pool)
    .await
    .expect("Failed to seed default group");

    sqlx::query(
        "CREATE TABLE clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL UNIQUE,
            mac_address TEXT,
            hostname TEXT,
            first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            query_count INTEGER NOT NULL DEFAULT 0,
            last_mac_update DATETIME,
            last_hostname_update DATETIME,
            group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            comment TEXT
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create clients table");

    sqlx::query(
        "CREATE TABLE query_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            record_type TEXT NOT NULL DEFAULT 'A',
            client_ip TEXT NOT NULL DEFAULT '127.0.0.1',
            blocked INTEGER NOT NULL DEFAULT 0,
            response_time_ms INTEGER,
            cache_hit INTEGER NOT NULL DEFAULT 0,
            cache_refresh INTEGER NOT NULL DEFAULT 0,
            dnssec_status TEXT,
            dns64_synthesized INTEGER NOT NULL DEFAULT 0,
            answers TEXT,
            upstream_server TEXT,
            upstream_pool TEXT,
            response_status TEXT,
            query_source TEXT NOT NULL DEFAULT 'client',
            protocol TEXT,
            group_id INTEGER,
            block_source TEXT,
            coalesced TEXT,
            created_at DATETIME NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create query_log table");

    sqlx::raw_sql(include_str!(
        "../../../../migrations/20260923000001_create_query_log_rollups.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to create query log rollups");

    sqlx::raw_sql(include_str!(
        "../../../../migrations/20261027000001_create_query_log_hour_rollups.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to create query log hour rollups");

    sqlx::query(
        "CREATE TABLE managed_domains (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL UNIQUE,
            domain     TEXT    NOT NULL,
            action     TEXT    NOT NULL CHECK(action IN ('allow', 'deny')),
            group_id   INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id),
            comment    TEXT,
            enabled    INTEGER NOT NULL DEFAULT 1,
            service_id TEXT,
            created_at TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create managed_domains table");

    sqlx::query(
        "CREATE TABLE regex_filters (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL UNIQUE,
            pattern    TEXT    NOT NULL,
            action     TEXT    NOT NULL CHECK(action IN ('allow', 'deny')),
            group_id   INTEGER NOT NULL DEFAULT 1,
            comment    TEXT,
            enabled    INTEGER NOT NULL DEFAULT 1,
            created_at TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at TEXT    NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create regex_filters table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS blocklist_sources (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT    NOT NULL UNIQUE,
            url         TEXT,
            group_id    INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT,
            comment     TEXT,
            enabled     BOOLEAN NOT NULL DEFAULT 1,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_synced_at TEXT,
            last_status INTEGER
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create blocklist_sources table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS blocklist_source_groups (
            source_id INTEGER NOT NULL REFERENCES blocklist_sources(id) ON DELETE CASCADE,
            group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            PRIMARY KEY (source_id, group_id)
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create blocklist_source_groups table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS whitelist_sources (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            name       TEXT    NOT NULL UNIQUE,
            url        TEXT,
            group_id   INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id),
            comment    TEXT,
            enabled    BOOLEAN NOT NULL DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_synced_at TEXT,
            last_status INTEGER
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create whitelist_sources table");

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS whitelist_source_groups (
            source_id INTEGER NOT NULL REFERENCES whitelist_sources(id) ON DELETE CASCADE,
            group_id  INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
            PRIMARY KEY (source_id, group_id)
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create whitelist_source_groups table");

    sqlx::raw_sql(include_str!(
        "../../../../migrations/20260214000001_create_client_subnets.sql"
    ))
    .execute(&pool)
    .await
    .expect("Failed to create client_subnets table");

    pool
}

/// App with `[auth]` enabled for the `admin` account in [`auth`]; with
/// `totp_enrolled`, logins also need [`auth::TOTP_CODE`].
pub async fn create_pihole_test_app_with_auth(
    pool: sqlx::SqlitePool,
    totp_enrolled: bool,
) -> Router {
    create_pihole_router_with_openapi(build_pihole_state(pool, true, totp_enrolled).await).0
}

async fn build_pihole_state(
    pool: sqlx::SqlitePool,
    auth_enabled: bool,
    totp_enrolled: bool,
) -> PiholeAppState {
    let db_config = DatabaseConfig::default();
    let client_repo = Arc::new(SqliteClientRepository::new(pool.clone(), &db_config));
    let subnet_repo = Arc::new(SqliteClientSubnetRepository::new(pool.clone()));
    let query_log_repo = Arc::new(SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &db_config,
        Default::default(),
    ));
    let group_repo = Arc::new(SqliteGroupRepository::new(pool.clone()));
    let managed_domain_repo = Arc::new(SqliteManagedDomainRepository::new(pool.clone()));
    let regex_filter_repo = Arc::new(SqliteRegexFilterRepository::new(pool.clone()));
    let blocklist_source_repo = Arc::new(SqliteBlocklistSourceRepository::new(pool.clone()));
    let whitelist_source_repo = Arc::new(SqliteWhitelistSourceRepository::new(pool.clone()));

    let block_filter_engine: Arc<dyn BlockFilterEnginePort> = Arc::new(MockBlockFilterEngine {
        blocking_enabled: AtomicBool::new(true),
    });

    let mut config = Config::default();
    config.auth.enabled = auth_enabled;
    config.auth.admin.username = "admin".to_string();
    let config = Arc::new(RwLock::new(config));

    PiholeAppState {
        query: PiholeQueryState {
            get_stats: Arc::new(GetQueryStatsUseCase::new(
                query_log_repo.clone(),
                client_repo.clone(),
            )),
            get_timeline: Arc::new(GetTimelineUseCase::new(query_log_repo.clone())),
            get_top_blocked_domains: Arc::new(GetTopBlockedDomainsUseCase::new(
                query_log_repo.clone(),
            )),
            get_top_allowed_domains: Arc::new(GetTopAllowedDomainsUseCase::new(
                query_log_repo.clone(),
            )),
            get_top_clients: Arc::new(GetTopClientsUseCase::new(query_log_repo.clone())),
            get_top_blocked_clients: Arc::new(GetTopBlockedClientsUseCase::new(
                query_log_repo.clone(),
            )),
            get_client_activity: Arc::new(GetClientActivityUseCase::new(query_log_repo.clone())),
            get_query_log_storage: Arc::new(GetQueryLogStorageUseCase::new(query_log_repo.clone())),
            get_recent_queries: Arc::new(GetRecentQueriesUseCase::new(query_log_repo.clone())),
            get_query_rate: Arc::new(GetQueryRateUseCase::new(query_log_repo.clone())),
            get_unique_domains: Arc::new(GetUniqueDomainsUseCase::new(query_log_repo.clone())),
        },
        blocking: PiholeBlockingState {
            block_filter_engine: block_filter_engine.clone(),
            get_managed_domains: Arc::new(GetManagedDomainsUseCase::new(
                managed_domain_repo.clone(),
            )),
            create_managed_domain: Arc::new(CreateManagedDomainUseCase::new(
                managed_domain_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            update_managed_domain: Arc::new(UpdateManagedDomainUseCase::new(
                managed_domain_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            delete_managed_domain: Arc::new(DeleteManagedDomainUseCase::new(
                managed_domain_repo,
                block_filter_engine.clone(),
            )),
            get_regex_filters: Arc::new(GetRegexFiltersUseCase::new(regex_filter_repo.clone())),
            create_regex_filter: Arc::new(CreateRegexFilterUseCase::new(
                regex_filter_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            update_regex_filter: Arc::new(UpdateRegexFilterUseCase::new(
                regex_filter_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            delete_regex_filter: Arc::new(DeleteRegexFilterUseCase::new(
                regex_filter_repo,
                block_filter_engine.clone(),
            )),
            blocking_timer: Arc::new(tokio::sync::Mutex::new(None)),
        },
        lists: PiholeListsState {
            get_blocklist_sources: Arc::new(GetBlocklistSourcesUseCase::new(
                blocklist_source_repo.clone(),
            )),
            create_blocklist_source: Arc::new(CreateBlocklistSourceUseCase::new(
                blocklist_source_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            update_blocklist_source: Arc::new(UpdateBlocklistSourceUseCase::new(
                blocklist_source_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            delete_blocklist_source: Arc::new(DeleteBlocklistSourceUseCase::new(
                blocklist_source_repo,
                block_filter_engine.clone(),
            )),
            get_whitelist_sources: Arc::new(GetWhitelistSourcesUseCase::new(
                whitelist_source_repo.clone(),
            )),
            create_whitelist_source: Arc::new(CreateWhitelistSourceUseCase::new(
                whitelist_source_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            update_whitelist_source: Arc::new(UpdateWhitelistSourceUseCase::new(
                whitelist_source_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            delete_whitelist_source: Arc::new(DeleteWhitelistSourceUseCase::new(
                whitelist_source_repo,
                block_filter_engine.clone(),
            )),
        },
        groups: PiholeGroupState {
            get_groups: Arc::new(GetGroupsUseCase::new(group_repo.clone())),
            create_group: Arc::new(CreateGroupUseCase::new(group_repo.clone())),
            update_group: Arc::new(UpdateGroupUseCase::new(group_repo.clone())),
            delete_group: Arc::new(DeleteGroupUseCase::new(
                group_repo.clone(),
                block_filter_engine.clone(),
                config.clone(),
            )),
        },
        clients: PiholeClientState {
            get_clients: Arc::new(GetClientsUseCase::new(client_repo.clone())),
            create_manual_client: Arc::new(CreateManualClientUseCase::new(
                client_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            update_client: Arc::new(UpdateClientUseCase::new(
                client_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            set_client_comment: Arc::new(SetClientCommentUseCase::new(client_repo.clone())),
            delete_client: Arc::new(DeleteClientUseCase::new(
                client_repo,
                block_filter_engine.clone(),
            )),
            get_client_subnets: Arc::new(GetClientSubnetsUseCase::new(subnet_repo.clone())),
            create_client_subnet: Arc::new(CreateClientSubnetUseCase::new(
                subnet_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            update_client_subnet: Arc::new(UpdateClientSubnetUseCase::new(
                subnet_repo.clone(),
                group_repo.clone(),
                block_filter_engine.clone(),
            )),
            delete_client_subnet: Arc::new(DeleteClientSubnetUseCase::new(
                subnet_repo,
                block_filter_engine.clone(),
            )),
        },
        system: PiholeSystemState {
            cleanup_query_logs: Arc::new(CleanupOldQueryLogsUseCase::new(query_log_repo)),
            config,
            reload_config: None,
            process_start: std::time::Instant::now()
                .checked_sub(PROCESS_AGE)
                .expect("monotonic clock is older than PROCESS_AGE"),
            https_port: 0,
            dns_cache: Arc::new(StubDnsCache),
        },
        auth: auth::build_auth_state(totp_enrolled).await,
    }
}

/// App with `[auth]` disabled, so every route is open — the routes' own tests
/// don't have to log in first.
pub async fn create_pihole_test_app(pool: sqlx::SqlitePool) -> Router {
    create_pihole_router_with_openapi(build_pihole_state(pool, false, false).await).0
}

/// [`create_pihole_test_app`] with `configure` applied to its live config.
pub async fn create_pihole_test_app_with_config(
    pool: sqlx::SqlitePool,
    configure: impl FnOnce(&mut Config),
) -> Router {
    let state = build_pihole_state(pool, false, false).await;
    configure(&mut *state.system.config.write().await);
    create_pihole_router_with_openapi(state).0
}

/// Sends a body-less `method uri` to `app`, returning the status and the JSON
/// body, or `Value::Null` when the body is empty or not JSON.
pub async fn send(
    app: Router,
    method: &str,
    uri: &str,
) -> (axum::http::StatusCode, serde_json::Value) {
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method(method)
                .uri(uri)
                .body(axum::body::Body::empty())
                .expect("failed to build request"),
        )
        .await
        .expect("request failed");
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("failed to read body")
        .to_bytes();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
    )
}

/// The OpenAPI document served next to [`create_pihole_test_app`].
pub async fn create_pihole_test_openapi(pool: sqlx::SqlitePool) -> utoipa::openapi::OpenApi {
    create_pihole_router_with_openapi(build_pihole_state(pool, false, false).await).1
}

pub async fn insert_query(
    pool: &sqlx::SqlitePool,
    domain: &str,
    client_ip: &str,
    blocked: bool,
    cache_hit: bool,
    block_source: Option<&str>,
) {
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, query_source, block_source)
         VALUES (?, 'A', ?, ?, 100, ?, 'client', ?)",
    )
    .bind(domain)
    .bind(client_ip)
    .bind(if blocked { 1i64 } else { 0i64 })
    .bind(if cache_hit { 1i64 } else { 0i64 })
    .bind(block_source)
    .execute(pool)
    .await
    .expect("Failed to insert query log entry");

    rebuild_rollups(pool).await;
}

/// Inserts an allowed query answered by `upstream_server` in `upstream_pool`.
pub async fn insert_upstream_query(
    pool: &sqlx::SqlitePool,
    domain: &str,
    upstream_pool: &str,
    upstream_server: &str,
) {
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, query_source, upstream_pool, upstream_server)
         VALUES (?, 'A', '10.0.0.1', 0, 100, 0, 'client', ?, ?)",
    )
    .bind(domain)
    .bind(upstream_pool)
    .bind(upstream_server)
    .execute(pool)
    .await
    .expect("Failed to insert query log entry");

    rebuild_rollups(pool).await;
}

/// Inserts an allowed query answered from a local DNS record.
pub async fn insert_local_dns_query(pool: &sqlx::SqlitePool, domain: &str) {
    sqlx::query(
        "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, query_source, response_status)
         VALUES (?, 'A', '10.0.0.1', 0, 1, 0, 'client', 'LOCAL_DNS')",
    )
    .bind(domain)
    .execute(pool)
    .await
    .expect("Failed to insert local DNS query");

    rebuild_rollups(pool).await;
}

/// Stats, top lists and counts read the rollups; rebuild them with the production
/// backfill and the hourly reference, every past hour held.
pub async fn rebuild_rollups(pool: &sqlx::SqlitePool) {
    sqlx::raw_sql(concat!(
        "DELETE FROM query_log_minute; DELETE FROM query_log_minute_record_type;",
        "DELETE FROM query_log_minute_block_source; DELETE FROM query_log_minute_upstream;",
        "DELETE FROM query_log_hour_domain; DELETE FROM query_log_hour_client;",
        "UPDATE query_log_rollup_state SET value = 0",
        " WHERE name IN ('minute_since', 'hour_since', 'hour_floor');",
        "UPDATE query_log_rollup_state SET value = CAST(strftime('%s', 'now') AS INTEGER) / 3600 * 3600",
        " WHERE name = 'hour_until';",
        include_str!("../../../../migrations/20260923000002_backfill_query_log_rollups.sql"),
        include_str!("../../../infrastructure/tests/support/hour_rollups.sql"),
    ))
    .execute(pool)
    .await
    .expect("Failed to rebuild query log rollups");
}

/// Inserts a client row with `last_seen = CURRENT_TIMESTAMP` so it counts
/// toward `unique_clients` in the stats aggregation.
pub async fn insert_client(pool: &sqlx::SqlitePool, ip_address: &str) {
    sqlx::query(
        "INSERT OR IGNORE INTO clients (ip_address, first_seen, last_seen)
         VALUES (?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
    )
    .bind(ip_address)
    .execute(pool)
    .await
    .expect("Failed to insert client");
}
