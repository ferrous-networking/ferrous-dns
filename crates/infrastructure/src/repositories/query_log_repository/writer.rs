use super::rollup::{minute_bucket, MinuteRollup};
use chrono::Utc;
use compact_str::{CompactString, ToCompactString};
use ferrous_dns_domain::{BlockSource, QueryLog, QuerySource, RecordType};
use sqlx::SqlitePool;
use std::fmt::Write as _;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const COLS_PER_ROW: usize = 18;
const ROWS_PER_CHUNK: usize = 999 / COLS_PER_ROW;

/// Upper bound on how many answer addresses are persisted per row. CDN domains
/// routinely return a dozen; keeping the first few bounds the size of a table
/// that grows to millions of rows.
const MAX_LOGGED_ANSWERS: usize = 4;

pub(super) struct QueryLogEntry {
    pub(super) domain: CompactString,
    pub(super) record_type: RecordType,
    pub(super) client_ip: CompactString,
    pub(super) blocked: bool,
    pub(super) response_time_us: Option<i64>,
    pub(super) cache_hit: bool,
    pub(super) cache_refresh: bool,
    pub(super) dnssec_status: Option<&'static str>,
    pub(super) dns64_synthesized: bool,
    pub(super) answers: Option<Arc<Vec<IpAddr>>>,
    pub(super) upstream_server: Option<Arc<str>>,
    pub(super) upstream_pool: Option<Arc<str>>,
    pub(super) response_status: Option<&'static str>,
    pub(super) query_source: QuerySource,
    pub(super) group_id: Option<i64>,
    pub(super) block_source: Option<BlockSource>,
    pub(super) protocol: Option<&'static str>,
}

impl QueryLogEntry {
    pub fn from_query_log(q: &QueryLog) -> Self {
        Self {
            domain: CompactString::from(q.domain.as_ref()),
            record_type: q.record_type,
            client_ip: q.client_ip.to_compact_string(),
            blocked: q.blocked,
            response_time_us: q.response_time_us.map(|t| t as i64),
            cache_hit: q.cache_hit,
            cache_refresh: q.cache_refresh,
            dnssec_status: q.dnssec_status,
            dns64_synthesized: q.dns64_synthesized,
            // Only an `Arc` clone here: this runs synchronously on the DNS hot
            // path. Formatting happens in the flush task (see `flush_batch`).
            answers: q.answers.clone().filter(|a| !a.is_empty()),
            upstream_server: q.upstream_server.clone(),
            upstream_pool: q.upstream_pool.clone(),
            response_status: q.response_status,
            query_source: q.query_source,
            group_id: q.group_id,
            block_source: q.block_source,
            protocol: q.protocol.map(|p| p.as_str()),
        }
    }
}

fn build_multi_insert_sql(n: usize) -> String {
    debug_assert!(n > 0 && n <= ROWS_PER_CHUNK);
    const HEADER: &str = "INSERT INTO query_log \
        (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, \
         cache_refresh, dnssec_status, dns64_synthesized, upstream_server, upstream_pool, response_status, query_source, group_id, block_source, answers, protocol, created_at) \
        VALUES ";
    const PLACEHOLDER: &str = "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
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

/// Comma-joined text form of the first `MAX_LOGGED_ANSWERS` addresses.
fn format_answers(addresses: &[IpAddr]) -> String {
    let mut out = String::new();
    for (i, ip) in addresses.iter().take(MAX_LOGGED_ANSWERS).enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(out, "{ip}");
    }
    out
}

pub(super) async fn flush_loop(
    pool: SqlitePool,
    mut receiver: mpsc::Receiver<QueryLogEntry>,
    max_batch_size: usize,
    flush_interval_ms: u64,
) {
    let mut batch: Vec<QueryLogEntry> = Vec::with_capacity(max_batch_size);
    let mut flush_interval = tokio::time::interval(Duration::from_millis(flush_interval_ms));

    loop {
        tokio::select! {
            maybe_entry = receiver.recv() => {
                match maybe_entry {
                    Some(entry) => {
                        batch.push(entry);
                        while batch.len() < max_batch_size {
                            match receiver.try_recv() {
                                Ok(e) => batch.push(e),
                                Err(_) => break,
                            }
                        }
                        if batch.len() >= max_batch_size {
                            flush_batch(&pool, &mut batch).await;
                        }
                    }
                    None => {
                        if !batch.is_empty() { flush_batch(&pool, &mut batch).await; }
                        info!("Query log flush task shutting down");
                        return;
                    }
                }
            }
            _ = flush_interval.tick() => {
                if !batch.is_empty() { flush_batch(&pool, &mut batch).await; }
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
    // One clock read stamps the raw rows and picks the rollup bucket, so the two
    // can never disagree about which minute a row belongs to.
    let now = Utc::now();
    let created_at = now.format("%Y-%m-%d %H:%M:%S").to_string();
    let bucket = minute_bucket(now.timestamp());

    let mut tx = match pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            error!(error = %e, count, "Failed to begin transaction for batch flush");
            batch.clear();
            return;
        }
    };

    let mut rollup = MinuteRollup::default();
    let mut inserted = 0usize;
    let mut errors = 0usize;

    for chunk in batch.chunks(ROWS_PER_CHUNK) {
        let sql = build_multi_insert_sql(chunk.len());
        // Rendered up-front so the borrows outlive the bind loop below.
        let answers: Vec<Option<String>> = chunk
            .iter()
            .map(|entry| {
                entry
                    .answers
                    .as_deref()
                    .map(|addrs| format_answers(addrs.as_slice()))
            })
            .collect();
        let mut q = sqlx::query(&sql);
        for (entry, answers) in chunk.iter().zip(&answers) {
            q = q
                .bind(entry.domain.as_str())
                .bind(entry.record_type.as_str())
                .bind(entry.client_ip.as_str())
                .bind(if entry.blocked { 1i64 } else { 0i64 })
                .bind(entry.response_time_us)
                .bind(if entry.cache_hit { 1i64 } else { 0i64 })
                .bind(if entry.cache_refresh { 1i64 } else { 0i64 })
                .bind(entry.dnssec_status)
                .bind(if entry.dns64_synthesized { 1i64 } else { 0i64 })
                .bind(entry.upstream_server.as_deref())
                .bind(entry.upstream_pool.as_deref())
                .bind(entry.response_status)
                .bind(entry.query_source.as_str())
                .bind(entry.group_id)
                .bind(entry.block_source.map(|s| s.to_str()))
                .bind(answers.as_deref())
                .bind(entry.protocol)
                .bind(created_at.as_str());
        }
        match q.execute(&mut *tx).await {
            Ok(r) => {
                inserted += r.rows_affected() as usize;
                // Only rows that landed are counted, so the rollup stays an
                // exact aggregate of the raw table.
                chunk.iter().for_each(|entry| rollup.add(entry));
            }
            Err(e) => {
                errors += chunk.len();
                warn!(error = %e, chunk_size = chunk.len(), "Failed to insert query log chunk");
            }
        }
    }

    if let Err(e) = rollup.persist(&mut tx, bucket).await {
        // Dropping `tx` rolls the raw rows back too: better to lose a batch than
        // to leave dashboard counts disagreeing with the log.
        error!(error = %e, count, "Failed to update query log rollups; batch discarded");
        batch.clear();
        return;
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
