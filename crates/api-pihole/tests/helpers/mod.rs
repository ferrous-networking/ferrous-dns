#![allow(dead_code)]

use async_trait::async_trait;
use axum::Router;
use ferrous_dns_api_pihole::state::{
    PiholeBlockingState, PiholeClientState, PiholeGroupState, PiholeListsState, PiholeQueryState,
    PiholeSystemState,
};
use ferrous_dns_api_pihole::{create_pihole_routes, PiholeAppState};
use ferrous_dns_application::ports::{
    BlockFilterEnginePort, FilterDecision, UpstreamGroupHealth, UpstreamHealthPort, UpstreamStatus,
};
use ferrous_dns_application::use_cases::{
    AssignClientGroupUseCase, CleanupOldQueryLogsUseCase, CreateBlocklistSourceUseCase,
    CreateGroupUseCase, CreateManagedDomainUseCase, CreateManualClientUseCase,
    CreateRegexFilterUseCase, CreateWhitelistSourceUseCase, DeleteBlocklistSourceUseCase,
    DeleteClientUseCase, DeleteGroupUseCase, DeleteManagedDomainUseCase, DeleteRegexFilterUseCase,
    DeleteWhitelistSourceUseCase, GetBlockFilterStatsUseCase, GetBlocklistSourcesUseCase,
    GetCacheStatsUseCase, GetClientsUseCase, GetGroupsUseCase, GetManagedDomainsUseCase,
    GetQueryStatsUseCase, GetRecentQueriesUseCase, GetRegexFiltersUseCase, GetTimelineUseCase,
    GetTopAllowedDomainsUseCase, GetTopBlockedDomainsUseCase, GetTopClientsUseCase,
    GetWhitelistSourcesUseCase, UpdateBlocklistSourceUseCase, UpdateClientUseCase,
    UpdateGroupUseCase, UpdateManagedDomainUseCase, UpdateRegexFilterUseCase,
    UpdateWhitelistSourceUseCase,
};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_domain::Config;
use ferrous_dns_domain::DomainError;
use ferrous_dns_infrastructure::repositories::{
    blocklist_source_repository::SqliteBlocklistSourceRepository,
    client_repository::SqliteClientRepository, group_repository::SqliteGroupRepository,
    managed_domain_repository::SqliteManagedDomainRepository,
    query_log_repository::SqliteQueryLogRepository,
    regex_filter_repository::SqliteRegexFilterRepository,
    whitelist_source_repository::SqliteWhitelistSourceRepository,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Mock: BlockFilterEnginePort
// ---------------------------------------------------------------------------

struct MockBlockFilterEngine;

#[async_trait]
impl BlockFilterEnginePort for MockBlockFilterEngine {
    fn resolve_group(&self, _ip: IpAddr) -> i64 {
        1
    }

    fn check(&self, _domain: &str, _group_id: i64) -> FilterDecision {
        FilterDecision::Allow
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
        true
    }

    fn set_blocking_enabled(&self, _enabled: bool) {}
}

// ---------------------------------------------------------------------------
// Mock: UpstreamHealthPort
// ---------------------------------------------------------------------------

struct MockUpstreamHealth;

impl UpstreamHealthPort for MockUpstreamHealth {
    fn get_all_upstream_status(&self) -> Vec<(String, UpstreamStatus)> {
        Vec::new()
    }

    fn get_grouped_upstream_health(&self) -> Vec<UpstreamGroupHealth> {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// Test DB + App builder
// ---------------------------------------------------------------------------

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
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
            upstream_server TEXT,
            upstream_pool TEXT,
            response_status TEXT,
            query_source TEXT NOT NULL DEFAULT 'client',
            group_id INTEGER,
            block_source TEXT,
            created_at DATETIME NOT NULL DEFAULT (datetime('now'))
        )",
    )
    .execute(&pool)
    .await
    .expect("Failed to create query_log table");

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
            updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
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
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
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

    pool
}

pub async fn create_pihole_test_app(pool: sqlx::SqlitePool, api_key: Option<&str>) -> Router {
    let db_config = DatabaseConfig::default();
    let client_repo = Arc::new(SqliteClientRepository::new(pool.clone(), &db_config));
    let query_log_repo = Arc::new(SqliteQueryLogRepository::new(
        pool.clone(),
        pool.clone(),
        pool.clone(),
        &db_config,
    ));
    let group_repo = Arc::new(SqliteGroupRepository::new(pool.clone()));
    let managed_domain_repo = Arc::new(SqliteManagedDomainRepository::new(pool.clone()));
    let regex_filter_repo = Arc::new(SqliteRegexFilterRepository::new(pool.clone()));
    let blocklist_source_repo = Arc::new(SqliteBlocklistSourceRepository::new(pool.clone()));
    let whitelist_source_repo = Arc::new(SqliteWhitelistSourceRepository::new(pool.clone()));

    let block_filter_engine: Arc<dyn BlockFilterEnginePort> = Arc::new(MockBlockFilterEngine);

    let state = PiholeAppState {
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
            get_recent_queries: Arc::new(GetRecentQueriesUseCase::new(query_log_repo.clone())),
            upstream_health: Arc::new(MockUpstreamHealth),
            get_block_filter_stats: Arc::new(GetBlockFilterStatsUseCase::new(
                block_filter_engine.clone(),
            )),
            get_cache_stats: Arc::new(GetCacheStatsUseCase::new(query_log_repo.clone())),
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
            )),
            update_blocklist_source: Arc::new(UpdateBlocklistSourceUseCase::new(
                blocklist_source_repo.clone(),
                group_repo.clone(),
            )),
            delete_blocklist_source: Arc::new(DeleteBlocklistSourceUseCase::new(
                blocklist_source_repo,
            )),
            get_whitelist_sources: Arc::new(GetWhitelistSourcesUseCase::new(
                whitelist_source_repo.clone(),
            )),
            create_whitelist_source: Arc::new(CreateWhitelistSourceUseCase::new(
                whitelist_source_repo.clone(),
                group_repo.clone(),
            )),
            update_whitelist_source: Arc::new(UpdateWhitelistSourceUseCase::new(
                whitelist_source_repo.clone(),
                group_repo.clone(),
            )),
            delete_whitelist_source: Arc::new(DeleteWhitelistSourceUseCase::new(
                whitelist_source_repo,
            )),
        },
        groups: PiholeGroupState {
            get_groups: Arc::new(GetGroupsUseCase::new(group_repo.clone())),
            create_group: Arc::new(CreateGroupUseCase::new(group_repo.clone())),
            update_group: Arc::new(UpdateGroupUseCase::new(group_repo.clone())),
            delete_group: Arc::new(DeleteGroupUseCase::new(group_repo.clone())),
        },
        clients: PiholeClientState {
            get_clients: Arc::new(GetClientsUseCase::new(client_repo.clone())),
            create_manual_client: Arc::new(CreateManualClientUseCase::new(
                client_repo.clone(),
                group_repo.clone(),
            )),
            update_client: Arc::new(UpdateClientUseCase::new(client_repo.clone())),
            delete_client: Arc::new(DeleteClientUseCase::new(client_repo.clone())),
            assign_client_group: Arc::new(AssignClientGroupUseCase::new(
                client_repo,
                group_repo,
                block_filter_engine,
            )),
        },
        system: PiholeSystemState {
            cleanup_query_logs: Arc::new(CleanupOldQueryLogsUseCase::new(query_log_repo)),
            config: Arc::new(RwLock::new(Config::default())),
            config_path: None,
            process_start: std::time::Instant::now(),
        },
        api_key: api_key.map(Arc::from),
    };

    create_pihole_routes(state)
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
