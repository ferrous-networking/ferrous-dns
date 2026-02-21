use ferrous_dns_domain::config::DatabaseConfig;
use ferrous_dns_infrastructure::database::{create_read_pool, create_write_pool};
use sqlx::SqlitePool;
use tracing::{error, info};

pub async fn init_database(
    database_url: &str,
    cfg: &DatabaseConfig,
) -> anyhow::Result<(SqlitePool, SqlitePool)> {
    info!("Initializing database: {}", database_url);

    let write_pool = create_write_pool(database_url, cfg).await.map_err(|e| {
        error!("Failed to initialize write pool: {}", e);
        anyhow::anyhow!(e)
    })?;

    let read_pool = create_read_pool(database_url, cfg).await.map_err(|e| {
        error!("Failed to initialize read pool: {}", e);
        anyhow::anyhow!(e)
    })?;

    info!(
        "Database initialized successfully (write_pool max={}, read_pool max={})",
        cfg.write_pool_max_connections, cfg.read_pool_max_connections,
    );

    Ok((write_pool, read_pool))
}
