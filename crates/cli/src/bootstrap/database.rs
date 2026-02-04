use ferrous_dns_infrastructure::database::create_pool;
use sqlx::SqlitePool;
use tracing::{error, info};

pub async fn init_database(database_url: &str) -> anyhow::Result<SqlitePool> {
    info!("Initializing database: {}", database_url);

    match create_pool(database_url).await {
        Ok(pool) => {
            info!("Database initialized successfully");
            Ok(pool)
        }
        Err(e) => {
            error!("Failed to initialize database: {}", e);
            Err(e.into())
        }
    }
}
