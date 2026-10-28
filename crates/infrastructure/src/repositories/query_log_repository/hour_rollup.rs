//! Hourly aggregates of client queries, for the top lists. A background job fills them
//! from the raw log one closed hour at a time (`roll_up_hours`); reads take the hours
//! they hold and the raw rows around them (`split_hours`). Schema in the
//! `*_query_log_hour_rollups` migration, SQL reference in `tests/support/hour_rollups.sql`.

use super::rollup::{bucket_ts, ceil_bucket, hour_bucket, HOUR_SECS};
use crate::repositories::sql_ts;
use chrono::{DateTime, Utc};
use sqlx::{Executor, Sqlite, SqliteConnection, SqlitePool};

/// How long after an hour ends before the job aggregates it. A flush stamps its rows
/// when it runs, so the last rows of an hour land just after the hour has closed.
const CLOSE_LAG_SECS: i64 = 60;

/// Rows per insert: four binds each, within SQLite's 999-variable floor.
const ROWS_PER_INSERT: usize = 999 / 4;

/// Hours in `[since, until)` are held completely. `floor` is retention's cutoff
/// rounded up: no hour before it is filled, its raw rows may be going away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Coverage {
    since: i64,
    until: i64,
    floor: i64,
}

impl Coverage {
    async fn read<'e, E>(executor: E) -> Result<Self, sqlx::Error>
    where
        E: Executor<'e, Database = Sqlite>,
    {
        let (since, until, floor) =
            sqlx::query_as("SELECT hour_since, hour_until, hour_floor FROM query_log_rollup_state")
                .fetch_one(executor)
                .await?;
        Ok(Self {
            since,
            until,
            floor,
        })
    }

    /// Replaces the coverage with `next`, inside `tx`, if it still is `self`. The
    /// update is the transaction's first statement, so it takes the write lock and
    /// waits out a busy writer; a transaction that reads first cannot wait when it
    /// upgrades.
    async fn replace(self, tx: &mut SqliteConnection, next: Coverage) -> Result<bool, sqlx::Error> {
        let replaced = sqlx::query(
            "UPDATE query_log_rollup_state SET hour_since = ?, hour_until = ?
             WHERE hour_since = ? AND hour_until = ? AND hour_floor = ?",
        )
        .bind(next.since)
        .bind(next.until)
        .bind(self.since)
        .bind(self.until)
        .bind(self.floor)
        .execute(&mut *tx)
        .await?
        .rows_affected();
        Ok(replaced == 1)
    }
}

/// Start of the first hour the clock has not closed yet: every hour before it ended at
/// least `CLOSE_LAG_SECS` ago.
fn first_open_hour() -> i64 {
    hour_bucket(Utc::now().timestamp() - CLOSE_LAG_SECS)
}

/// A window ending now, split for the hourly rollups: raw rows in `[cutoff, lead_end)`
/// and from `tail_start` on, buckets in `[from, until)`.
pub(super) struct HourSplit {
    pub cutoff: String,
    pub lead_end: String,
    pub from: i64,
    pub until: i64,
    pub tail_start: String,
}

/// Run the read that binds the split on the same transaction, so a retention run in
/// between cannot move the coverage under it.
pub(super) async fn split_hours<'e, E>(
    executor: E,
    start: DateTime<Utc>,
) -> Result<HourSplit, sqlx::Error>
where
    E: Executor<'e, Database = Sqlite>,
{
    let coverage = Coverage::read(executor).await?;
    let cutoff_secs = start.timestamp();
    let from = ceil_bucket(cutoff_secs, HOUR_SECS).max(coverage.since);
    // Hours held beyond the clock were closed by a clock that ran ahead; it has since
    // stepped back and logs rows into them again, so they are read raw until the job
    // gives them back.
    let held_until = coverage.until.min(first_open_hour());
    // Without a held hour inside the window, the whole window is a raw tail.
    let (from, until) = if from < held_until {
        (from, held_until)
    } else {
        (cutoff_secs, cutoff_secs)
    };
    Ok(HourSplit {
        cutoff: sql_ts(start),
        lead_end: bucket_ts(from)?,
        tail_start: bucket_ts(until)?,
        from,
        until,
    })
}

/// Aggregates up to `max_hours` closed hours the rollups do not hold yet: the hours
/// after the last one held first, then the history before the first one, newest
/// first. Returns how many it stored.
///
/// Each hour is aggregated on the read pool, so the write lock is held only to store
/// it. A retention run that moved the coverage in between turns the store into a
/// no-op, since retention may be deleting that hour's rows.
pub(super) async fn roll_up_hours(
    read_pool: &SqlitePool,
    write_pool: &SqlitePool,
    max_hours: u32,
) -> Result<u32, sqlx::Error> {
    let mut stored = 0;
    for _ in 0..max_hours {
        let coverage = Coverage::read(read_pool).await?;
        let open = first_open_hour();
        if coverage.until > open {
            give_back_open_hours(write_pool, coverage, open).await?;
            continue;
        }
        let Some(hour) = next_hour(read_pool, coverage, open).await? else {
            break;
        };
        let domains = aggregate(read_pool, "domain", hour).await?;
        let clients = aggregate(read_pool, "client_ip", hour).await?;
        if store(write_pool, coverage, hour, &domains, &clients).await? {
            stored += 1;
        }
    }
    Ok(stored)
}

async fn next_hour(
    pool: &SqlitePool,
    coverage: Coverage,
    first_open: i64,
) -> Result<Option<i64>, sqlx::Error> {
    if coverage.until < first_open {
        return Ok(Some(coverage.until));
    }
    let oldest: Option<i64> = sqlx::query_scalar(
        "SELECT CAST(strftime('%s', MIN(created_at)) AS INTEGER)
         FROM query_log WHERE query_source = 'client'",
    )
    .fetch_one(pool)
    .await?;
    let previous = coverage.since - HOUR_SECS;
    // While retention deletes in batches the oldest row is still below its cutoff:
    // `floor` is what keeps the job off an hour that is being deleted.
    Ok(oldest
        .filter(|&oldest| previous >= hour_bucket(oldest).max(coverage.floor))
        .map(|_| previous))
}

/// Drops the hours held from `first_open` on, which a clock running ahead closed too
/// early, unless the coverage changed since it was read.
async fn give_back_open_hours(
    pool: &SqlitePool,
    read_as: Coverage,
    first_open: i64,
) -> Result<(), sqlx::Error> {
    let next = Coverage {
        since: read_as.since.min(first_open),
        until: first_open,
        ..read_as
    };
    let mut tx = pool.begin().await?;
    if !read_as.replace(&mut tx, next).await? {
        return Ok(());
    }
    for table in ["query_log_hour_domain", "query_log_hour_client"] {
        sqlx::query(&format!("DELETE FROM {table} WHERE bucket >= ?"))
            .bind(first_open)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await
}

type HourCounts = Vec<(String, i64, i64)>;

async fn aggregate(
    pool: &SqlitePool,
    key_column: &str,
    hour: i64,
) -> Result<HourCounts, sqlx::Error> {
    sqlx::query_as(&format!(
        "SELECT {key_column}, blocked != 0, COUNT(*) FROM query_log
         WHERE query_source = 'client' AND created_at >= ? AND created_at < ?
         GROUP BY 1, 2"
    ))
    .bind(bucket_ts(hour)?)
    .bind(bucket_ts(hour + HOUR_SECS)?)
    .fetch_all(pool)
    .await
}

/// Stores one hour and extends the coverage over it, unless the coverage is no
/// longer the one the hour was picked from.
async fn store(
    pool: &SqlitePool,
    picked_from: Coverage,
    hour: i64,
    domains: &HourCounts,
    clients: &HourCounts,
) -> Result<bool, sqlx::Error> {
    let next = if hour == picked_from.until {
        Coverage {
            until: hour + HOUR_SECS,
            ..picked_from
        }
    } else {
        Coverage {
            since: hour,
            ..picked_from
        }
    };
    let mut tx = pool.begin().await?;
    if !picked_from.replace(&mut tx, next).await? {
        return Ok(false);
    }
    for (table, key_column, counts) in [
        ("query_log_hour_domain", "domain", domains),
        ("query_log_hour_client", "client_ip", clients),
    ] {
        sqlx::query(&format!("DELETE FROM {table} WHERE bucket = ?"))
            .bind(hour)
            .execute(&mut *tx)
            .await?;
        for chunk in counts.chunks(ROWS_PER_INSERT) {
            let values = vec!["(?, ?, ?, ?)"; chunk.len()].join(", ");
            let sql = format!(
                "INSERT INTO {table} (bucket, {key_column}, blocked, count) VALUES {values}"
            );
            let mut q = sqlx::query(&sql);
            for (key, blocked, count) in chunk {
                q = q.bind(hour).bind(key).bind(blocked).bind(count);
            }
            q.execute(&mut *tx).await?;
        }
    }
    tx.commit().await?;
    Ok(true)
}
