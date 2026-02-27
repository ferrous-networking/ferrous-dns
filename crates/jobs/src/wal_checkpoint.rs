use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

pub struct WalCheckpointJob {
    pool: SqlitePool,
    interval_secs: u64,
    shutdown: CancellationToken,
}

impl WalCheckpointJob {
    pub fn new(pool: SqlitePool, interval_secs: u64) -> Self {
        Self {
            pool,
            interval_secs,
            shutdown: CancellationToken::new(),
        }
    }

    pub fn with_interval(mut self, interval_secs: u64) -> Self {
        self.interval_secs = interval_secs;
        self
    }

    pub fn with_cancellation(mut self, token: CancellationToken) -> Self {
        self.shutdown = token;
        self
    }

    pub async fn start(self: Arc<Self>) {
        info!(
            interval_secs = self.interval_secs,
            "Starting WAL checkpoint job (PASSIVE mode)"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                tokio::select! {
                    _ = self.shutdown.cancelled() => {
                        info!("WalCheckpointJob: shutting down");
                        break;
                    }
                    _ = interval.tick() => {
                        match sqlx::query("PRAGMA wal_checkpoint(PASSIVE)")
                            .execute(&self.pool)
                            .await
                        {
                            Ok(_) => {
                                info!("WAL passive checkpoint completed");
                            }
                            Err(e) => {
                                error!(error = %e, "WAL checkpoint failed");
                            }
                        }
                    }
                }
            }
        });
    }
}
