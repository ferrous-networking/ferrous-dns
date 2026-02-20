use async_trait::async_trait;
use compact_str::CompactString;
use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_domain::{BlockSource, DomainError, QueryLog, QuerySource, QueryStats};
use sqlx::{sqlite::SqliteRow, Row, SqlitePool};
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::mpsc;
use tracing::{debug, error, info, instrument, warn};

const CHANNEL_CAPACITY: usize = 10_000;
const MAX_BATCH_SIZE: usize = 500;
const FLUSH_INTERVAL_MS: u64 = 100;

/// Number of columns per row in `query_log` INSERT.
const COLS_PER_ROW: usize = 13;
/// SQLite's default SQLITE_LIMIT_VARIABLE_NUMBER is 999.
/// Each chunk inserts at most this many rows in a single statement.
const ROWS_PER_CHUNK: usize = 999 / COLS_PER_ROW; // 76

/// Build `INSERT INTO query_log (...) VALUES (?,…), (?,…), …` for `n` rows.
fn build_multi_insert_sql(n: usize) -> String {
    debug_assert!(n > 0 && n <= ROWS_PER_CHUNK);
    const HEADER: &str = "INSERT INTO query_log \
        (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, \
         cache_refresh, dnssec_status, upstream_server, response_status, query_source, group_id, block_source) \
        VALUES ";
    const PLACEHOLDER: &str = "(?,?,?,?,?,?,?,?,?,?,?,?,?)";
    let mut sql = String::with_capacity(HEADER.len() + n * (PLACEHOLDER.len() + 1));
    sql.push_str(HEADER);
    for i in 0..n {
        if i > 0 {
            sql.push(',');
        }
        sql.push_str(PLACEHOLDER);
    }
    sql
}

struct QueryLogEntry {
    domain: CompactString,
    record_type: CompactString,
    client_ip: Arc<str>,
    blocked: bool,
    response_time_ms: Option<i64>,
    cache_hit: bool,
    cache_refresh: bool,
    dnssec_status: Option<&'static str>,
    upstream_server: Option<Arc<str>>,
    response_status: Option<&'static str>,
    query_source: CompactString,
    group_id: Option<i64>,
    block_source: Option<&'static str>,
}

impl QueryLogEntry {
    fn from_query_log(q: &QueryLog) -> Self {
        Self {
            domain: CompactString::from(q.domain.as_ref()),
            record_type: CompactString::from(q.record_type.as_str()),
            client_ip: Arc::from(q.client_ip.to_string()),
            blocked: q.blocked,
            response_time_ms: q.response_time_us.map(|t| t as i64),
            cache_hit: q.cache_hit,
            cache_refresh: q.cache_refresh,
            dnssec_status: q.dnssec_status,
            upstream_server: q.upstream_server.as_ref().map(|s| Arc::from(s.as_str())),
            response_status: q.response_status,
            query_source: CompactString::from(q.query_source.as_str()),
            group_id: q.group_id,
            block_source: q.block_source.map(|s| s.to_str()),
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

fn row_to_query_log(row: SqliteRow) -> Option<QueryLog> {
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
    let query_source = QuerySource::from_str(&query_source_str).unwrap_or(QuerySource::Client);

    let block_source: Option<BlockSource> =
        row.get::<Option<String>, _>("block_source")
            .and_then(|s| match s.as_str() {
                "blocklist" => Some(BlockSource::Blocklist),
                "managed_domain" => Some(BlockSource::ManagedDomain),
                "regex_filter" => Some(BlockSource::RegexFilter),
                _ => None,
            });

    Some(QueryLog {
        id: Some(row.get("id")),
        domain: Arc::from(domain_str.as_str()),
        record_type: record_type_str.parse().ok()?,
        client_ip: client_ip_str.parse().ok()?,
        blocked: row.get::<i64, _>("blocked") != 0,
        response_time_us: row
            .get::<Option<i64>, _>("response_time_ms") // column kept as-is (SQLite no ALTER COLUMN)
            .map(|t| t as u64),
        cache_hit: row.get::<i64, _>("cache_hit") != 0,
        cache_refresh: row.get::<i64, _>("cache_refresh") != 0,
        dnssec_status,
        upstream_server: row.get::<Option<String>, _>("upstream_server"),
        response_status,
        timestamp: Some(row.get("created_at")),
        query_source,
        group_id: row.get("group_id"),
        block_source,
    })
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

        let start = std::time::Instant::now();

        let mut tx = match pool.begin().await {
            Ok(tx) => tx,
            Err(e) => {
                error!(error = %e, count, "Failed to begin transaction for batch flush");
                batch.clear();
                return;
            }
        };

        let mut inserted = 0usize;
        let mut errors = 0usize;

        for chunk in batch.chunks(ROWS_PER_CHUNK) {
            let sql = build_multi_insert_sql(chunk.len());
            let mut q = sqlx::query(&sql);
            for entry in chunk {
                q = q
                    .bind(entry.domain.as_str())
                    .bind(entry.record_type.as_str())
                    .bind(entry.client_ip.as_ref())
                    .bind(if entry.blocked { 1i64 } else { 0i64 })
                    .bind(entry.response_time_ms)
                    .bind(if entry.cache_hit { 1i64 } else { 0i64 })
                    .bind(if entry.cache_refresh { 1i64 } else { 0i64 })
                    .bind(entry.dnssec_status)
                    .bind(entry.upstream_server.as_deref())
                    .bind(entry.response_status)
                    .bind(entry.query_source.as_str())
                    .bind(entry.group_id)
                    .bind(entry.block_source);
            }
            match q.execute(&mut *tx).await {
                Ok(r) => inserted += r.rows_affected() as usize,
                Err(e) => {
                    errors += chunk.len();
                    warn!(error = %e, chunk_size = chunk.len(), "Failed to insert query log chunk");
                }
            }
        }

        match tx.commit().await {
            Ok(_) => {
                let elapsed = start.elapsed();
                debug!(
                    count = inserted,
                    errors,
                    duration_ms = elapsed.as_millis(),
                    throughput = (inserted as f64 / elapsed.as_secs_f64()) as u64,
                    "Batch flushed"
                );
            }
            Err(e) => {
                error!(error = %e, count, "Failed to commit batch transaction");
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
    async fn get_recent(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        debug!(
            limit = limit,
            period_hours = period_hours,
            "Fetching recent queries with time filter"
        );

        let rows = sqlx::query(
            "SELECT id, domain, record_type, client_ip, blocked, response_time_ms, cache_hit, cache_refresh, dnssec_status, upstream_server, response_status, query_source, group_id, block_source,
                    datetime(created_at) as created_at
             FROM query_log
             WHERE created_at >= datetime('now', '-' || ? || ' hours')
               AND query_source = 'client'
             ORDER BY created_at DESC
             LIMIT ?",
        )
        .bind(period_hours)
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch recent queries");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        let entries: Vec<QueryLog> = rows.into_iter().filter_map(row_to_query_log).collect();

        debug!(count = entries.len(), "Recent queries fetched successfully");
        Ok(entries)
    }

    #[instrument(skip(self))]
    async fn get_recent_paged(
        &self,
        limit: u32,
        offset: u32,
        period_hours: f32,
    ) -> Result<(Vec<QueryLog>, u64), DomainError> {
        debug!(
            limit = limit,
            offset = offset,
            period_hours = period_hours,
            "Fetching paginated queries"
        );

        let count_row = sqlx::query(
            "SELECT COUNT(*) as total FROM query_log
             WHERE created_at >= datetime('now', '-' || ? || ' hours')
               AND query_source = 'client'",
        )
        .bind(period_hours)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to count queries");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        let total = count_row.get::<i64, _>("total") as u64;

        let rows = sqlx::query(
            "SELECT id, domain, record_type, client_ip, blocked, response_time_ms, cache_hit, cache_refresh, dnssec_status, upstream_server, response_status, query_source, group_id, block_source,
                    datetime(created_at) as created_at
             FROM query_log
             WHERE created_at >= datetime('now', '-' || ? || ' hours')
               AND query_source = 'client'
             ORDER BY created_at DESC
             LIMIT ? OFFSET ?",
        )
        .bind(period_hours)
        .bind(limit as i64)
        .bind(offset as i64)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch paginated queries");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        let entries: Vec<QueryLog> = rows.into_iter().filter_map(row_to_query_log).collect();

        debug!(
            count = entries.len(),
            total = total,
            "Paginated queries fetched"
        );
        Ok((entries, total))
    }

    #[instrument(skip(self))]
    async fn get_stats(&self, period_hours: f32) -> Result<QueryStats, DomainError> {
        debug!(
            period_hours = period_hours,
            "Fetching query statistics with Phase 4 analytics (optimized single-pass)"
        );

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
             WHERE response_time_ms IS NOT NULL
               AND created_at >= datetime('now', '-' || ? || ' hours')
               AND query_source = 'client'",
        )
        .bind(period_hours)
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

        let type_rows = sqlx::query(
            "SELECT record_type, COUNT(*) as count
             FROM query_log
             WHERE created_at >= datetime('now', '-' || ? || ' hours')
               AND query_source = 'client'
             GROUP BY record_type",
        )
        .bind(period_hours)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch type distribution");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        let mut queries_by_type = std::collections::HashMap::new();
        for type_row in type_rows {
            let type_str: String = type_row.get("record_type");
            let count: i64 = type_row.get("count");

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

    #[instrument(skip(self))]
    async fn get_timeline(
        &self,
        period_hours: u32,
        granularity: &str,
    ) -> Result<Vec<ferrous_dns_application::ports::TimelineBucket>, DomainError> {
        debug!(
            period_hours = period_hours,
            granularity = granularity,
            "Fetching query timeline"
        );

        let time_bucket_expr = match granularity {
            "minute" => "strftime('%Y-%m-%d %H:%M:00', created_at)".to_string(),
            "quarter_hour" => "strftime('%Y-%m-%d %H:', created_at) || \
                 printf('%02d', (CAST(strftime('%M', created_at) AS INTEGER) / 15) * 15) || \
                 ':00'"
                .to_string(),
            "hour" => "strftime('%Y-%m-%d %H:00:00', created_at)".to_string(),
            "day" => "strftime('%Y-%m-%d 00:00:00', created_at)".to_string(),
            _ => "strftime('%Y-%m-%d %H:00:00', created_at)".to_string(),
        };

        let sql = format!(
            "SELECT
                {} as time_bucket,
                COUNT(*) as total,
                SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked,
                SUM(CASE WHEN blocked = 0 THEN 1 ELSE 0 END) as unblocked
             FROM query_log
             WHERE created_at >= datetime('now', '-' || ? || ' hours')
               AND query_source = 'client'
             GROUP BY time_bucket
             ORDER BY time_bucket ASC",
            time_bucket_expr
        );

        let rows = sqlx::query(&sql)
            .bind(period_hours as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to fetch timeline");
                DomainError::InvalidDomainName(format!("Database error: {}", e))
            })?;

        let timeline: Vec<ferrous_dns_application::ports::TimelineBucket> = rows
            .into_iter()
            .map(|row| ferrous_dns_application::ports::TimelineBucket {
                timestamp: row.get("time_bucket"),
                total: row.get::<i64, _>("total") as u64,
                blocked: row.get::<i64, _>("blocked") as u64,
                unblocked: row.get::<i64, _>("unblocked") as u64,
            })
            .collect();

        debug!(buckets = timeline.len(), "Timeline fetched successfully");
        Ok(timeline)
    }

    #[instrument(skip(self))]
    async fn count_queries_since(&self, seconds_ago: i64) -> Result<u64, DomainError> {
        debug!(
            seconds_ago = seconds_ago,
            "Counting queries since N seconds ago"
        );

        let row = sqlx::query(
            "SELECT COUNT(*) as count
             FROM query_log
             WHERE created_at >= datetime('now', '-' || ? || ' seconds')",
        )
        .bind(seconds_ago)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to count queries");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        let count = row.get::<i64, _>("count") as u64;
        debug!(count = count, "Query count retrieved");
        Ok(count)
    }

    #[instrument(skip(self))]
    async fn get_cache_stats(
        &self,
        period_hours: f32,
    ) -> Result<ferrous_dns_application::ports::CacheStats, DomainError> {
        debug!(period_hours = period_hours, "Fetching cache statistics");

        let row = sqlx::query(
            "SELECT
                COUNT(*) as total_queries,
                SUM(CASE WHEN cache_hit = 1 AND cache_refresh = 0 THEN 1 ELSE 0 END) as hits,
                SUM(CASE WHEN cache_refresh = 1 THEN 1 ELSE 0 END) as refreshes,
                SUM(CASE WHEN cache_hit = 0 AND cache_refresh = 0 AND blocked = 0 THEN 1 ELSE 0 END) as misses
             FROM query_log
             WHERE created_at >= datetime('now', '-' || ? || ' hours')",
        )
        .bind(period_hours)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to fetch cache statistics");
            DomainError::InvalidDomainName(format!("Database error: {}", e))
        })?;

        let total_hits = row.get::<i64, _>("hits") as u64;
        let total_misses = row.get::<i64, _>("misses") as u64;
        let total_refreshes = row.get::<i64, _>("refreshes") as u64;
        let total_queries = total_hits + total_misses;

        let hit_rate = if total_queries > 0 {
            (total_hits as f64 / total_queries as f64) * 100.0
        } else {
            0.0
        };

        let refresh_rate = if total_hits > 0 {
            (total_refreshes as f64 / total_hits as f64) * 100.0
        } else {
            0.0
        };

        debug!(
            total_hits = total_hits,
            total_misses = total_misses,
            total_refreshes = total_refreshes,
            hit_rate = hit_rate,
            "Cache statistics retrieved"
        );

        Ok(ferrous_dns_application::ports::CacheStats {
            total_hits,
            total_misses,
            total_refreshes,
            hit_rate,
            refresh_rate,
        })
    }

    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError> {
        let result = sqlx::query(
            "DELETE FROM query_log WHERE created_at < datetime('now', '-' || ? || ' days')",
        )
        .bind(days as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to delete old query logs");
            DomainError::DatabaseError(format!("Failed to delete old query logs: {}", e))
        })?;

        let deleted = result.rows_affected();
        info!(deleted, days, "Old query logs deleted");
        Ok(deleted)
    }
}

static START_TIME: std::sync::OnceLock<SystemTime> = std::sync::OnceLock::new();

fn get_uptime() -> u64 {
    let start = START_TIME.get_or_init(SystemTime::now);
    start.elapsed().unwrap_or_default().as_secs()
}
