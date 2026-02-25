use ferrous_dns_domain::config::DatabaseConfig;
use sqlx::migrate::Migrator;
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteConnection, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
    SqliteSynchronous,
};
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

fn base_options(database_url: &str) -> Result<SqliteConnectOptions, sqlx::Error> {
    SqliteConnectOptions::from_str(database_url).map(|o| {
        o.create_if_missing(true)
            .foreign_keys(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal)
    })
}

async fn apply_per_connection_pragmas(conn: &mut SqliteConnection) -> Result<(), sqlx::Error> {
    sqlx::query("PRAGMA cache_size = -65536")
        .execute(&mut *conn)
        .await?;
    sqlx::query("PRAGMA mmap_size = 268435456")
        .execute(&mut *conn)
        .await?;
    sqlx::query("PRAGMA temp_store = MEMORY")
        .execute(&mut *conn)
        .await?;
    Ok(())
}

pub async fn create_write_pool(
    database_url: &str,
    cfg: &DatabaseConfig,
) -> Result<SqlitePool, sqlx::Error> {
    let options =
        base_options(database_url)?.busy_timeout(Duration::from_secs(cfg.write_busy_timeout_secs));

    let pool = SqlitePoolOptions::new()
        .max_connections(cfg.write_pool_max_connections)
        .min_connections(1)
        .acquire_timeout(Duration::from_secs(cfg.write_busy_timeout_secs))
        .after_connect(|conn, _| Box::pin(async move { apply_per_connection_pragmas(conn).await }))
        .connect_with(options)
        .await?;

    sqlx::query(&format!(
        "PRAGMA wal_autocheckpoint = {}",
        cfg.wal_autocheckpoint
    ))
    .execute(&pool)
    .await?;

    let migrator = Migrator::new(Path::new("./migrations")).await?;
    migrator.run(&pool).await?;

    sqlx::query("PRAGMA optimize").execute(&pool).await?;

    Ok(pool)
}

pub async fn create_read_pool(
    database_url: &str,
    cfg: &DatabaseConfig,
) -> Result<SqlitePool, sqlx::Error> {
    let options =
        base_options(database_url)?.busy_timeout(Duration::from_secs(cfg.read_busy_timeout_secs));

    let pool = SqlitePoolOptions::new()
        .max_connections(cfg.read_pool_max_connections)
        .min_connections(2)
        .acquire_timeout(Duration::from_secs(cfg.read_acquire_timeout_secs))
        .after_connect(|conn, _| Box::pin(async move { apply_per_connection_pragmas(conn).await }))
        .connect_with(options)
        .await?;

    Ok(pool)
}

pub async fn create_pool(database_url: &str) -> Result<SqlitePool, sqlx::Error> {
    let cfg = DatabaseConfig::default();
    create_write_pool(database_url, &cfg).await
}
