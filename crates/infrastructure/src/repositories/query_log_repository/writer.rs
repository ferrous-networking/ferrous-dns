use compact_str::{CompactString, ToCompactString};
use ferrous_dns_domain::QueryLog;
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

const COLS_PER_ROW: usize = 14;
const ROWS_PER_CHUNK: usize = 999 / COLS_PER_ROW;

pub(super) struct QueryLogEntry {
    domain: CompactString,
    record_type: CompactString,
    client_ip: CompactString,
    blocked: bool,
    response_time_ms: Option<i64>,
    cache_hit: bool,
    cache_refresh: bool,
    dnssec_status: Option<&'static str>,
    upstream_server: Option<Arc<str>>,
    upstream_pool: Option<Arc<str>>,
    response_status: Option<&'static str>,
    query_source: CompactString,
    group_id: Option<i64>,
    block_source: Option<&'static str>,
}

impl QueryLogEntry {
    pub fn from_query_log(q: &QueryLog) -> Self {
        Self {
            domain: CompactString::from(q.domain.as_ref()),
            record_type: CompactString::from(q.record_type.as_str()),
            client_ip: q.client_ip.to_compact_string(),
            blocked: q.blocked,
            response_time_ms: q.response_time_us.map(|t| t as i64),
            cache_hit: q.cache_hit,
            cache_refresh: q.cache_refresh,
            dnssec_status: q.dnssec_status,
            upstream_server: q.upstream_server.clone(),
            upstream_pool: q.upstream_pool.clone(),
            response_status: q.response_status,
            query_source: CompactString::from(q.query_source.as_str()),
            group_id: q.group_id,
            block_source: q.block_source.map(|s| s.to_str()),
        }
    }
}

fn build_multi_insert_sql(n: usize) -> String {
    debug_assert!(n > 0 && n <= ROWS_PER_CHUNK);
    const HEADER: &str = "INSERT INTO query_log \
        (domain, record_type, client_ip, blocked, response_time_ms, cache_hit, \
         cache_refresh, dnssec_status, upstream_server, upstream_pool, response_status, query_source, group_id, block_source) \
        VALUES ";
    const PLACEHOLDER: &str = "(?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
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
                .bind(entry.client_ip.as_str())
                .bind(if entry.blocked { 1i64 } else { 0i64 })
                .bind(entry.response_time_ms)
                .bind(if entry.cache_hit { 1i64 } else { 0i64 })
                .bind(if entry.cache_refresh { 1i64 } else { 0i64 })
                .bind(entry.dnssec_status)
                .bind(entry.upstream_server.as_deref())
                .bind(entry.upstream_pool.as_deref())
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
