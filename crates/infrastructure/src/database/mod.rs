use ferrous_dns_domain::config::DatabaseConfig;
use sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool,
    SqlitePoolOptions, SqliteSynchronous,
};
use sqlx::Connection;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tracing::{info, warn};

mod compact;

pub use compact::{compact_database, CompactionReport};

/// Creates new databases with incremental auto-vacuum, so retention can give the pages it
/// frees back to the file. The pragma only takes effect on an empty database (sqlx issues
/// it before `journal_mode`); on an older file it is a no-op until `--compact-database`.
fn base_options(database_url: &str) -> Result<SqliteConnectOptions, sqlx::Error> {
    SqliteConnectOptions::from_str(database_url).map(|o| {
        o.create_if_missing(true)
            .foreign_keys(true)
            .auto_vacuum(SqliteAutoVacuum::Incremental)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
    })
}

/// Applied on every connection: these pragmas are per-connection state, and each pool
/// commits through its own connections (auto-checkpoints fire on the committing connection).
async fn apply_per_connection_pragmas(
    conn: &mut SqliteConnection,
    cache_size_kb: u32,
    mmap_size_mb: u32,
    wal_autocheckpoint: u32,
) -> Result<(), sqlx::Error> {
    let cache_pragma = format!("PRAGMA cache_size = -{}", cache_size_kb);
    let mmap_pragma = format!("PRAGMA mmap_size = {}", mmap_size_mb as u64 * 1024 * 1024);
    let checkpoint_pragma = format!("PRAGMA wal_autocheckpoint = {}", wal_autocheckpoint);
    sqlx::query(&cache_pragma).execute(&mut *conn).await?;
    sqlx::query(&mmap_pragma).execute(&mut *conn).await?;
    sqlx::query(&checkpoint_pragma).execute(&mut *conn).await?;
    sqlx::query("PRAGMA temp_store = MEMORY")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

async fn build_pool(
    database_url: &str,
    cfg: &DatabaseConfig,
    max_connections: u32,
    min_connections: u32,
    busy_timeout: Duration,
    acquire_timeout: Duration,
) -> Result<SqlitePool, sqlx::Error> {
    let options = base_options(database_url)?.busy_timeout(busy_timeout);
    let cache_kb = cfg.sqlite_cache_size_kb;
    let mmap_mb = cfg.sqlite_mmap_size_mb;
    let autocheckpoint = cfg.wal_autocheckpoint;
    SqlitePoolOptions::new()
        .max_connections(max_connections)
        .min_connections(min_connections)
        .acquire_timeout(acquire_timeout)
        .after_connect(move |conn, _| {
            Box::pin(async move {
                apply_per_connection_pragmas(conn, cache_kb, mmap_mb, autocheckpoint).await
            })
        })
        .connect_with(options)
        .await
}

fn wal_file_len(db_path: &Path) -> u64 {
    let mut wal = db_path.as_os_str().to_owned();
    wal.push("-wal");
    std::fs::metadata(wal).map_or(0, |m| m.len())
}

/// Copies the WAL a previous run left behind back into the database and truncates it.
///
/// A killed run never cleans up its WAL, and the first connection after it rebuilds the
/// WAL index by reading the whole file. On slow storage a large WAL takes minutes; inside
/// a pool that would race `acquire_timeout` and fail every start the same way, so this
/// runs on a connection of its own, before any pool exists.
async fn checkpoint_leftover_wal(options: &SqliteConnectOptions) -> Result<(), sqlx::Error> {
    let wal_bytes = wal_file_len(options.get_filename());
    if wal_bytes > 0 {
        info!(
            wal_bytes,
            "Checkpointing the WAL left by the previous run; a large one takes a while on slow storage"
        );
    }

    let started = Instant::now();
    let mut conn = SqliteConnection::connect_with(options).await?;
    let (busy, log_frames, checkpointed_frames): (i64, i64, i64) =
        sqlx::query_as("PRAGMA wal_checkpoint(TRUNCATE)")
            .fetch_one(&mut conn)
            .await?;
    conn.close().await?;

    if busy != 0 {
        warn!(
            log_frames,
            checkpointed_frames,
            "Another connection kept the WAL busy; starting without truncating it"
        );
    } else if wal_bytes > 0 {
        // A successful TRUNCATE reports the emptied log, so its frame counts are zero.
        info!(
            duration_ms = started.elapsed().as_millis() as u64,
            "WAL checkpointed and truncated"
        );
    }
    Ok(())
}

/// Planner statistics for `idx_query_log_window`, written when `sqlite_stat1` has none.
/// The id range and the distinct sources are index seeks (min and max in separate
/// subqueries, or SQLite scans), so this costs milliseconds at any size. Only the first
/// two numbers steer a plan here (retention skip-scans on rows per `query_source`), so
/// the per-timestamp ones stay at 1.
const SEED_QUERY_LOG_STATS: &str = "
    INSERT INTO sqlite_stat1 (tbl, idx, stat)
    SELECT 'query_log', 'idx_query_log_window',
           row_count || ' ' || ((row_count + source_count - 1) / source_count) || ' 1 1'
    FROM (
        SELECT (SELECT max(id) FROM query_log) - (SELECT min(id) FROM query_log) + 1 AS row_count,
               (WITH RECURSIVE source(v) AS (
                    SELECT min(query_source) FROM query_log
                    UNION ALL
                    SELECT (SELECT min(query_source) FROM query_log WHERE query_source > v)
                    FROM source WHERE v IS NOT NULL
                ) SELECT count(v) FROM source) AS source_count
    )
    WHERE row_count > 0
      AND NOT EXISTS (SELECT 1 FROM sqlite_stat1 WHERE idx = 'idx_query_log_window')";

/// Estimates the query log's missing statistics so the `PRAGMA optimize` that follows has
/// no reason to ANALYZE it.
///
/// ANALYZE counts every entry of an index exactly, whatever `analysis_limit` says. The
/// window index was built over the existing rows on upgrade, so on a multi-GB query log
/// that count read the whole index before DNS could start, and a boot killed during it
/// left no statistics for the next one.
async fn seed_missing_query_log_stats(conn: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    // Creates sqlite_stat1 on a database that was never analyzed.
    sqlx::query("ANALYZE sqlite_schema")
        .execute(&mut *conn)
        .await?;
    let seeded = sqlx::query(SEED_QUERY_LOG_STATS)
        .execute(&mut *conn)
        .await?
        .rows_affected();
    if seeded > 0 {
        // Statistics load with the schema; this reloads them on this connection.
        sqlx::query("ANALYZE sqlite_schema")
            .execute(&mut *conn)
            .await?;
        info!("Estimated the query log's planner statistics instead of analyzing it");
    }
    Ok(())
}

/// Free space an old database must hold before startup warns about it.
const UNRECLAIMABLE_WARN_BYTES: i64 = 64 * 1024 * 1024;

/// The free bytes worth a warning: only a database without auto-vacuum (`0`, created
/// before it was enabled) keeps its free pages forever.
fn unreclaimable_free_bytes(auto_vacuum: i64, freelist_pages: i64, page_size: i64) -> Option<i64> {
    let free = freelist_pages.saturating_mul(page_size);
    (auto_vacuum == 0 && free >= UNRECLAIMABLE_WARN_BYTES).then_some(free)
}

async fn warn_about_unreclaimable_space(conn: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    let auto_vacuum: i64 = sqlx::query_scalar("PRAGMA auto_vacuum")
        .fetch_one(&mut *conn)
        .await?;
    let freelist_pages: i64 = sqlx::query_scalar("PRAGMA freelist_count")
        .fetch_one(&mut *conn)
        .await?;
    let page_size: i64 = sqlx::query_scalar("PRAGMA page_size")
        .fetch_one(&mut *conn)
        .await?;
    if let Some(free) = unreclaimable_free_bytes(auto_vacuum, freelist_pages, page_size) {
        warn!(
            free_mib = free / (1024 * 1024),
            "The database file holds free space it cannot give back, because it was created \
             before incremental auto-vacuum; stop the server and run \
             `ferrous-dns --compact-database` once to reclaim it"
        );
    }
    Ok(())
}

pub async fn create_write_pool(
    database_url: &str,
    cfg: &DatabaseConfig,
) -> Result<SqlitePool, sqlx::Error> {
    let busy = Duration::from_secs(cfg.write_busy_timeout_secs);
    checkpoint_leftover_wal(&base_options(database_url)?.busy_timeout(busy)).await?;

    let pool = build_pool(
        database_url,
        cfg,
        cfg.write_pool_max_connections,
        1,
        busy,
        busy,
    )
    .await?;

    sqlx::migrate!("../../migrations").run(&pool).await?;
    crate::repositories::client_subnet_repository::canonicalize_stored_subnets(&pool).await?;

    let mut conn = pool.acquire().await?;
    seed_missing_query_log_stats(&mut conn).await?;
    sqlx::query("PRAGMA optimize").execute(&mut *conn).await?;
    warn_about_unreclaimable_space(&mut conn).await?;
    drop(conn);

    Ok(pool)
}

pub async fn create_query_log_pool(
    database_url: &str,
    cfg: &DatabaseConfig,
) -> Result<SqlitePool, sqlx::Error> {
    let busy = Duration::from_secs(cfg.write_busy_timeout_secs);
    build_pool(
        database_url,
        cfg,
        cfg.query_log_pool_max_connections,
        1,
        busy,
        busy,
    )
    .await
}

pub async fn create_read_pool(
    database_url: &str,
    cfg: &DatabaseConfig,
) -> Result<SqlitePool, sqlx::Error> {
    build_pool(
        database_url,
        cfg,
        cfg.read_pool_max_connections,
        2,
        Duration::from_secs(cfg.read_busy_timeout_secs),
        Duration::from_secs(cfg.read_acquire_timeout_secs),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::{unreclaimable_free_bytes, UNRECLAIMABLE_WARN_BYTES};

    const PAGE: i64 = 4096;
    const WARN_PAGES: i64 = UNRECLAIMABLE_WARN_BYTES / PAGE;

    #[test]
    fn an_old_database_with_enough_free_space_is_reported() {
        assert_eq!(
            unreclaimable_free_bytes(0, WARN_PAGES, PAGE),
            Some(UNRECLAIMABLE_WARN_BYTES)
        );
    }

    #[test]
    fn little_free_space_is_not_reported() {
        assert_eq!(unreclaimable_free_bytes(0, WARN_PAGES - 1, PAGE), None);
    }

    #[test]
    fn a_database_with_auto_vacuum_is_not_reported() {
        assert_eq!(unreclaimable_free_bytes(1, WARN_PAGES * 10, PAGE), None);
        assert_eq!(unreclaimable_free_bytes(2, WARN_PAGES * 10, PAGE), None);
    }
}
