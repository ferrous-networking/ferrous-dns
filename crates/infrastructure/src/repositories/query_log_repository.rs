use async_trait::async_trait;
use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_domain::{DomainError, QueryLog, QueryStats};
use sqlx::{Row, SqlitePool};
use std::time::SystemTime;
use tracing::{debug, error, instrument};

pub struct SqliteQueryLogRepository {
    pool: SqlitePool,
}

impl SqliteQueryLogRepository {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl QueryLogRepository for SqliteQueryLogRepository {
    #[instrument(skip(self, query), fields(domain = %query.domain, record_type = %query.record_type.as_str()))]
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError> {
        debug!("Logging DNS query");

        sqlx::query(
            "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, cache_refresh, dnssec_status)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&query.domain)
        .bind(query.record_type.as_str())
        .bind(query.client_ip.to_string())
        .bind(if query.blocked { 1 } else { 0 })
        .bind(query.response_time_ms.map(|t| t as i64))
        .bind(if query.cache_hit { 1 } else { 0 })
        .bind(if query.cache_refresh { 1 } else { 0 })
        .bind(query.dnssec_status.as_deref())  // NEW: DNSSEC status
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to log query");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        debug!("Query logged successfully");
        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_recent(&self, limit: u32) -> Result<Vec<QueryLog>, DomainError> {
        debug!(limit = limit, "Fetching recent queries");

        let rows = sqlx::query(
            "SELECT id, domain, record_type, client_ip, blocked, response_time_ms, cache_hit, cache_refresh, dnssec_status,
                    datetime(created_at) as created_at
             FROM query_log
             ORDER BY created_at DESC
             LIMIT ?",
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch recent queries");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        let entries: Vec<QueryLog> = rows
            .into_iter()
            .filter_map(|row| {
                let client_ip_str: String = row.get("client_ip");
                let record_type_str: String = row.get("record_type");

                Some(QueryLog {
                    id: Some(row.get("id")),
                    domain: row.get("domain"),
                    record_type: record_type_str.parse().ok()?,
                    client_ip: client_ip_str.parse().ok()?,
                    blocked: row.get::<i64, _>("blocked") != 0,
                    response_time_ms: row
                        .get::<Option<i64>, _>("response_time_ms")
                        .map(|t| t as u64),
                    cache_hit: row.get::<i64, _>("cache_hit") != 0,
                    cache_refresh: row.get::<i64, _>("cache_refresh") != 0,
                    dnssec_status: row.get::<Option<String>, _>("dnssec_status"),  // NEW
                    timestamp: Some(row.get("created_at")),
                })
            })
            .collect();

        debug!(count = entries.len(), "Recent queries fetched successfully");
        Ok(entries)
    }

    #[instrument(skip(self))]
    async fn get_stats(&self) -> Result<QueryStats, DomainError> {
        debug!("Fetching query statistics");

        let row = sqlx::query(
            "SELECT
                COUNT(*) as total,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN cache_hit = 1 THEN 1 ELSE 0 END) as cache_hits,
                COUNT(DISTINCT client_ip) as unique_clients,
                AVG(response_time_ms) as avg_time,
                AVG(CASE WHEN cache_hit = 1 THEN response_time_ms END) as avg_cache_time,
                AVG(CASE WHEN cache_hit = 0 AND blocked = 0 THEN response_time_ms END) as avg_upstream_time
             FROM query_log
             WHERE response_time_ms IS NOT NULL",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch statistics");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        let total = row.get::<i64, _>("total") as u64;
        let cache_hits = row.get::<i64, _>("cache_hits") as u64;
        let cache_hit_rate = if total > 0 {
            (cache_hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        let stats = QueryStats {
            queries_total: total,
            queries_blocked: row.get::<i64, _>("blocked") as u64,
            unique_clients: row.get::<i64, _>("unique_clients") as u64,
            uptime_seconds: get_uptime(),
            cache_hit_rate,
            avg_query_time_ms: row.get::<Option<f64>, _>("avg_time").unwrap_or(0.0),
            avg_cache_time_ms: row.get::<Option<f64>, _>("avg_cache_time").unwrap_or(0.0),
            avg_upstream_time_ms: row
                .get::<Option<f64>, _>("avg_upstream_time")
                .unwrap_or(0.0),
        };

        debug!(
            queries_total = stats.queries_total,
            queries_blocked = stats.queries_blocked,
            unique_clients = stats.unique_clients,
            cache_hit_rate = stats.cache_hit_rate,
            avg_query_time_ms = stats.avg_query_time_ms,
            avg_cache_time_ms = stats.avg_cache_time_ms,
            avg_upstream_time_ms = stats.avg_upstream_time_ms,
            "Statistics fetched successfully"
        );

        Ok(stats)
    }
}

static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

fn get_uptime() -> u64 {
    let start = START_TIME.get_or_init(SystemTime::now);
    start.elapsed().unwrap_or_default().as_secs()
}
