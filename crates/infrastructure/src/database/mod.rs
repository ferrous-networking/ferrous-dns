use ferrous_dns_domain::config::DatabaseConfig;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
    SqliteSynchronous,
};
use sqlx::Connection;
use std::path::Path;
use std::str::FromStr;
use std::time::{Duration, Instant};
use tracing::{info, warn};

fn base_options(database_url: &str) -> Result<SqliteConnectOptions, sqlx::Error> {
    SqliteConnectOptions::from_str(database_url).map(|o| {
        o.create_if_missing(true)
            .foreign_keys(true)
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
        info!(
            frames = checkpointed_frames,
            duration_ms = started.elapsed().as_millis() as u64,
            "WAL checkpointed and truncated"
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

    sqlx::query("PRAGMA optimize").execute(&pool).await?;

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
