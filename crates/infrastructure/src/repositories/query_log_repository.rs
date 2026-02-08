use async_trait::async_trait;
use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_domain::{DomainError, QueryLog, QuerySource, QueryStats};
use sqlx::{Row, SqlitePool};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

const CHANNEL_CAPACITY: usize = 10_000;
const MAX_BATCH_SIZE: usize = 500;
const FLUSH_INTERVAL_MS: u64 = 100;

/// Flattened entry for the channel (owned data, Send-safe).
struct QueryLogEntry {
    domain: String,
    record_type: String,
    client_ip: String,
    blocked: bool,
    response_time_ms: Option<i64>,
    cache_hit: bool,
    cache_refresh: bool,
    dnssec_status: Option<&'static str>,
    upstream_server: Option<String>,
    response_status: Option<&'static str>,
    query_source: String, // Phase 5: client, internal, dnssec_validation
}

impl QueryLogEntry {
    fn from_query_log(q: &QueryLog) -> Self {
        Self {
            domain: q.domain.to_string(),
            record_type: q.record_type.as_str().to_string(),
            client_ip: q.client_ip.to_string(),
            blocked: q.blocked,
            response_time_ms: q.response_time_ms.map(|t| t as i64),
            cache_hit: q.cache_hit,
            cache_refresh: q.cache_refresh,
            dnssec_status: q.dnssec_status,
            upstream_server: q.upstream_server.clone(),
            response_status: q.response_status,
            query_source: q.query_source.as_str().to_string(),
        }
    }
}

fn to_static_dnssec(s: &str) -> Option<&'static str> {
    match s {
        "Secure" => Some("Secure"),
        "Insecure" => Some("Insecure"),
        "Bogus" => Some("Bogus"),
        "Indeterminate" => Some("Indeterminate"),
        "Unknown" => Some("Unknown"),
        _ => None,
    }
}

fn to_static_response_status(s: &str) -> Option<&'static str> {
    match s {
        "NOERROR" => Some("NOERROR"),
        "NXDOMAIN" => Some("NXDOMAIN"),
        "SERVFAIL" => Some("SERVFAIL"),
        "REFUSED" => Some("REFUSED"),
        "TIMEOUT" => Some("TIMEOUT"),
        "BLOCKED" => Some("BLOCKED"),
        _ => None,
    }
}

pub struct SqliteQueryLogRepository {
    pool: SqlitePool,
    sender: mpsc::Sender<QueryLogEntry>,
}

impl SqliteQueryLogRepository {
    pub fn new(pool: SqlitePool) -> Self {
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);

        let flush_pool = pool.clone();
        tokio::spawn(async move {
            Self::flush_loop(flush_pool, receiver).await;
        });

        info!(
            channel_capacity = CHANNEL_CAPACITY,
            batch_size = MAX_BATCH_SIZE,
            flush_interval_ms = FLUSH_INTERVAL_MS,
            "Query log batching enabled"
        );

        Self { pool, sender }
    }

    async fn flush_loop(pool: SqlitePool, mut receiver: mpsc::Receiver<QueryLogEntry>) {
        let mut batch: Vec<QueryLogEntry> = Vec::with_capacity(MAX_BATCH_SIZE);
        let mut flush_interval = tokio::time::interval(Duration::from_millis(FLUSH_INTERVAL_MS));

        loop {
            tokio::select! {
                maybe_entry = receiver.recv() => {
                    match maybe_entry {
                        Some(entry) => {
                            batch.push(entry);
                            while batch.len() < MAX_BATCH_SIZE {
                                match receiver.try_recv() {
                                    Ok(e) => batch.push(e),
                                    Err(_) => break,
                                }
                            }
                            if batch.len() >= MAX_BATCH_SIZE {
                                Self::flush_batch(&pool, &mut batch).await;
                            }
                        }
                        None => {
                            if !batch.is_empty() { Self::flush_batch(&pool, &mut batch).await; }
                            info!("Query log flush task shutting down");
                            return;
                        }
                    }
                }
                _ = flush_interval.tick() => {
                    if !batch.is_empty() { Self::flush_batch(&pool, &mut batch).await; }
                }
            }
        }
    }

    async fn flush_batch(pool: &SqlitePool, batch: &mut Vec<QueryLogEntry>) {
        let count = batch.len();
        if count == 0 {
            return;
        }

        let mut sql = String::from(
            "INSERT INTO query_log (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, cache_refresh, dnssec_status, upstream_server, response_status, query_source) VALUES "
        );

        for (i, _) in batch.iter().enumerate() {
            if i > 0 {
                sql.push_str(", ");
            }
            sql.push_str("(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        }

        let mut query = sqlx::query(&sql);
        for entry in batch.iter() {
            query = query
                .bind(&entry.domain)
                .bind(&entry.record_type)
                .bind(&entry.client_ip)
                .bind(if entry.blocked { 1i64 } else { 0 })
                .bind(entry.response_time_ms)
                .bind(if entry.cache_hit { 1i64 } else { 0 })
                .bind(if entry.cache_refresh { 1i64 } else { 0 })
                .bind(entry.dnssec_status)
                .bind(entry.upstream_server.as_deref())
                .bind(entry.response_status)
                .bind(&entry.query_source);
        }

        match query.execute(pool).await {
            Ok(_) => {
                debug!(count, "Query log batch flushed");
            }
            Err(e) => {
                error!(error = %e, count, "Failed to flush query log batch");
            }
        }

        batch.clear();
    }
}

#[async_trait]
impl QueryLogRepository for SqliteQueryLogRepository {
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError> {
        let entry = QueryLogEntry::from_query_log(query);
        match self.sender.try_send(entry) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("Query log channel full, dropping entry");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("Query log channel closed");
                Ok(())
            }
        }
    }

    #[instrument(skip(self))]
    async fn get_recent(&self, limit: u32) -> Result<Vec<QueryLog>, DomainError> {
        debug!(limit = limit, "Fetching recent queries");

        let rows = sqlx::query(
            "SELECT id, domain, record_type, client_ip, blocked, response_time_ms, cache_hit, cache_refresh, dnssec_status, upstream_server, response_status, query_source,
                    datetime(created_at) as created_at
             FROM query_log ORDER BY created_at DESC LIMIT ?",
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
                let domain_str: String = row.get("domain");

                let dnssec_status: Option<&'static str> = row
                    .get::<Option<String>, _>("dnssec_status")
                    .and_then(|s| to_static_dnssec(&s));
                let response_status: Option<&'static str> = row
                    .get::<Option<String>, _>("response_status")
                    .and_then(|s| to_static_response_status(&s));

                let query_source_str: String = row
                    .get::<Option<String>, _>("query_source")
                    .unwrap_or_else(|| "client".to_string());
                let query_source =
                    QuerySource::from_str(&query_source_str).unwrap_or(QuerySource::Client);

                Some(QueryLog {
                    id: Some(row.get("id")),
                    domain: Arc::from(domain_str.as_str()),
                    record_type: record_type_str.parse().ok()?,
                    client_ip: client_ip_str.parse().ok()?,
                    blocked: row.get::<i64, _>("blocked") != 0,
                    response_time_ms: row
                        .get::<Option<i64>, _>("response_time_ms")
                        .map(|t| t as u64),
                    cache_hit: row.get::<i64, _>("cache_hit") != 0,
                    cache_refresh: row.get::<i64, _>("cache_refresh") != 0,
                    dnssec_status,
                    upstream_server: row.get::<Option<String>, _>("upstream_server"),
                    response_status,
                    timestamp: Some(row.get("created_at")),
                    query_source,
                })
            })
            .collect();

        debug!(count = entries.len(), "Recent queries fetched successfully");
        Ok(entries)
    }

    #[instrument(skip(self))]
    async fn get_stats(&self) -> Result<QueryStats, DomainError> {
        debug!("Fetching query statistics with Phase 4 analytics");

        let row = sqlx::query(
            "SELECT
                COUNT(*) as total,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN cache_hit = 1 THEN 1 ELSE 0 END) as cache_hits,
                COUNT(DISTINCT client_ip) as unique_clients,
                AVG(response_time_ms) as avg_time,
                AVG(CASE WHEN cache_hit = 1 THEN response_time_ms END) as avg_cache_time,
                AVG(CASE WHEN cache_hit = 0 AND blocked = 0 THEN response_time_ms END) as avg_upstream_time
             FROM query_log WHERE response_time_ms IS NOT NULL",
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

        // Phase 4: Fetch queries by type for analytics
        let type_rows = sqlx::query(
            "SELECT record_type, COUNT(*) as count FROM query_log GROUP BY record_type",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch type distribution");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        let mut queries_by_type = std::collections::HashMap::new();
        for row in type_rows {
            let type_str: String = row.get("record_type");
            let count: i64 = row.get("count");

            // Parse RecordType from string
            if let Ok(record_type) = type_str.parse::<ferrous_dns_domain::RecordType>() {
                queries_by_type.insert(record_type, count as u64);
            }
        }

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
            queries_by_type: std::collections::HashMap::new(),
            most_queried_type: None,
            record_type_distribution: Vec::new(),
        }
        .with_analytics(queries_by_type);

        debug!(
            queries_total = stats.queries_total,
            queries_blocked = stats.queries_blocked,
            unique_clients = stats.unique_clients,
            cache_hit_rate = stats.cache_hit_rate,
            most_queried_type = ?stats.most_queried_type,
            type_count = stats.queries_by_type.len(),
            "Statistics with analytics fetched successfully"
        );
        Ok(stats)
    }
}

static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

fn get_uptime() -> u64 {
    let start = START_TIME.get_or_init(SystemTime::now);
    start.elapsed().unwrap_or_default().as_secs()
}
