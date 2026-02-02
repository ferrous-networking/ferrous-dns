use async_trait::async_trait;
use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_domain::{DomainError, QueryLog, QueryStats, RecordType};
use sqlx::{Row, SqlitePool};
use std::net::IpAddr;
use std::str::FromStr;
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
    #[instrument(skip(self, query), fields(domain = %query.domain, record_type = %query.record_type.as_str()
    ))]
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError> {
        debug!("Logging DNS query");

        sqlx::query(
            "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&query.domain)
        .bind(query.record_type.as_str())
        .bind(query.client_ip.to_string())
        .bind(if query.blocked { 1 } else { 0 })
        .bind(query.response_time_ms.map(|t| t as i64))
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
            "SELECT id, domain, record_type, client_ip, blocked, response_time_ms,
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

        let entries: Vec<QueryLog> = rows // ← Type annotation adicionada
            .into_iter()
            .filter_map(|row| {
                let client_ip_str: String = row.get("client_ip");
                let record_type_str: String = row.get("record_type");

                Some(QueryLog {
                    id: Some(row.get("id")),
                    domain: row.get("domain"),
                    record_type: RecordType::from_str(&record_type_str)?,
                    client_ip: IpAddr::from_str(&client_ip_str).ok()?,
                    blocked: row.get::<i64, _>("blocked") != 0,
                    response_time_ms: row
                        .get::<Option<i64>, _>("response_time_ms")
                        .map(|t| t as u64),
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
                COUNT(DISTINCT client_ip) as unique_clients
             FROM query_log",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch statistics");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        let stats = QueryStats {
            queries_total: row.get::<i64, _>("total") as u64,
            queries_blocked: row.get::<i64, _>("blocked") as u64,
            unique_clients: row.get::<i64, _>("unique_clients") as u64,
            uptime_seconds: get_uptime(),
        };

        debug!(
            queries_total = stats.queries_total,
            queries_blocked = stats.queries_blocked,
            unique_clients = stats.unique_clients,
            "Statistics fetched successfully"
        );

        Ok(stats)
    }
}

static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

fn get_uptime() -> u64 {
    let start = START_TIME.get_or_init(|| SystemTime::now());
    start.elapsed().unwrap_or_default().as_secs()
}
