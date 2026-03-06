#![allow(dead_code)]

use axum::Router;
use ferrous_dns_api_pihole::{create_pihole_routes, PiholeAppState};
use ferrous_dns_application::use_cases::{
    GetQueryStatsUseCase, GetTimelineUseCase, GetTopBlockedDomainsUseCase, GetTopClientsUseCase,
};
use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::repositories::{
    client_repository::SqliteClientRepository, query_log_repository::SqliteQueryLogRepository,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::sync::Arc;

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
            group_id INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT,
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

    let state = PiholeAppState {
        get_stats: Arc::new(GetQueryStatsUseCase::new(
            query_log_repo.clone(),
            client_repo,
        )),
        get_timeline: Arc::new(GetTimelineUseCase::new(query_log_repo.clone())),
        get_top_blocked_domains: Arc::new(GetTopBlockedDomainsUseCase::new(query_log_repo.clone())),
        get_top_clients: Arc::new(GetTopClientsUseCase::new(query_log_repo)),
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
