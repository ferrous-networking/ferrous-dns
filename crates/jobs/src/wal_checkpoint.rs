use ferrous_dns_domain::DomainError;
use sqlx::{SqliteConnection, SqlitePool};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// A WAL past this many frames (64 MiB at SQLite's default 4 KiB page) is truncated.
/// PASSIVE checkpoints copy frames back but leave them valid, and the first start after
/// a kill has to recover every valid frame before it can open the database.
const TRUNCATE_THRESHOLD_FRAMES: i64 = 16_384;

/// How long a truncation may wait for readers to leave the WAL. New writers are held off
/// while it waits, so this stays far below the write busy timeout.
const TRUNCATE_BUSY_TIMEOUT_MS: i64 = 2_000;

/// Result of one checkpoint pass, parsed from a `(busy, log, checkpointed)` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalCheckpointOutcome {
    /// Every WAL frame was copied back into the database file.
    Complete { frames: i64 },
    /// The WAL had grown past the size limit; it was copied back and truncated to zero bytes.
    Truncated { frames: i64 },
    /// A reader's snapshot pinned the WAL, so only a prefix of the frames was copied back.
    Partial {
        log_frames: i64,
        checkpointed_frames: i64,
    },
    /// Another connection held a lock the checkpoint needed.
    Busy {
        log_frames: i64,
        checkpointed_frames: i64,
    },
    /// The database is not in WAL mode.
    NotWal,
}

fn db_err(e: sqlx::Error) -> DomainError {
    DomainError::DatabaseError(e.to_string())
}

impl WalCheckpointOutcome {
    fn from_row((busy, log_frames, checkpointed_frames): (i64, i64, i64)) -> Self {
        if log_frames == -1 {
            Self::NotWal
        } else if busy != 0 {
            Self::Busy {
                log_frames,
                checkpointed_frames,
            }
        } else if checkpointed_frames < log_frames {
            Self::Partial {
                log_frames,
                checkpointed_frames,
            }
        } else {
            Self::Complete { frames: log_frames }
        }
    }

    fn log_frames(self) -> i64 {
        match self {
            Self::Complete { frames } | Self::Truncated { frames } => frames,
            Self::Partial { log_frames, .. } | Self::Busy { log_frames, .. } => log_frames,
            Self::NotWal => -1,
        }
    }
}

/// Truncation waits for readers under a short busy timeout, then restores the
/// connection's own; if readers stay, SQLite falls back to a passive pass.
async fn truncate(
    conn: &mut SqliteConnection,
    log_frames: i64,
) -> Result<WalCheckpointOutcome, DomainError> {
    let (busy_timeout_ms,): (i64,) = sqlx::query_as("PRAGMA busy_timeout")
        .fetch_one(&mut *conn)
        .await
        .map_err(db_err)?;
    sqlx::query(&format!("PRAGMA busy_timeout = {TRUNCATE_BUSY_TIMEOUT_MS}"))
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    let row = sqlx::query_as::<_, (i64, i64, i64)>("PRAGMA wal_checkpoint(TRUNCATE)")
        .fetch_one(&mut *conn)
        .await;
    sqlx::query(&format!("PRAGMA busy_timeout = {busy_timeout_ms}"))
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;

    Ok(match row.map_err(db_err)? {
        (0, _, _) => WalCheckpointOutcome::Truncated { frames: log_frames },
        busy => WalCheckpointOutcome::from_row(busy),
    })
}

pub struct WalCheckpointJob {
    pool: SqlitePool,
    interval_secs: u64,
}

impl WalCheckpointJob {
    pub fn new(pool: SqlitePool, interval_secs: u64) -> Self {
        Self {
            pool,
            interval_secs,
        }
    }

    pub async fn checkpoint_once(&self) -> Result<WalCheckpointOutcome, DomainError> {
        let mut conn = self.pool.acquire().await.map_err(db_err)?;
        let passive = sqlx::query_as::<_, (i64, i64, i64)>("PRAGMA wal_checkpoint(PASSIVE)")
            .fetch_one(&mut *conn)
            .await
            .map(WalCheckpointOutcome::from_row)
            .map_err(db_err)?;

        let log_frames = passive.log_frames();
        if log_frames < TRUNCATE_THRESHOLD_FRAMES {
            return Ok(passive);
        }
        truncate(&mut conn, log_frames).await
    }

    pub fn spawn(self) {
        info!(
            interval_secs = self.interval_secs,
            "Starting WAL checkpoint job (PASSIVE mode, TRUNCATE past 64 MiB)"
        );

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(self.interval_secs));
            loop {
                interval.tick().await;
                match self.checkpoint_once().await {
                    Ok(WalCheckpointOutcome::Complete { frames }) => {
                        info!(frames, "WAL passive checkpoint completed")
                    }
                    Ok(WalCheckpointOutcome::Truncated { frames }) => {
                        info!(frames, "WAL past 64 MiB checkpointed and truncated")
                    }
                    Ok(WalCheckpointOutcome::Partial {
                        log_frames,
                        checkpointed_frames,
                    }) => warn!(
                        log_frames,
                        checkpointed_frames, "WAL passive checkpoint partial: readers pin the WAL"
                    ),
                    Ok(WalCheckpointOutcome::Busy {
                        log_frames,
                        checkpointed_frames,
                    }) => warn!(
                        log_frames,
                        checkpointed_frames, "WAL passive checkpoint blocked by a busy lock"
                    ),
                    Ok(WalCheckpointOutcome::NotWal) => {
                        debug!("WAL checkpoint skipped: database is not in WAL mode")
                    }
                    Err(e) => error!(error = %e, "WAL checkpoint failed"),
                }
            }
        });
    }
}
