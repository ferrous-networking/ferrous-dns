//! Hourly aggregates of client queries, for the top lists. A background job fills them
//! from the raw log one closed hour at a time (`roll_up_hours`); reads take the hours
//! they hold and the raw rows around them (`split_hours`). Schema in the
//! `*_query_log_hour_rollups` migration, SQL reference in `tests/support/hour_rollups.sql`.

use super::rollup::{ceil_bucket, hour_bucket, HOUR_SECS};
use crate::repositories::{sql_ts, unix_cutoff};
use chrono::{DateTime, Utc};
use sqlx::{Executor, Sqlite, SqlitePool};

/// How long after an hour ends before the job aggregates it. A flush stamps its rows
/// when it runs, so the last rows of an hour land just after the hour has closed.
const CLOSE_LAG_SECS: i64 = 60;

/// Rows per insert: four binds each, within SQLite's 999-variable floor.
const ROWS_PER_INSERT: usize = 999 / 4;

const READ_COVERAGE: &str = "SELECT
    (SELECT value FROM query_log_rollup_state WHERE name = 'hour_since'),
    (SELECT value FROM query_log_rollup_state WHERE name = 'hour_until'),
    (SELECT value FROM query_log_rollup_state WHERE name = 'hour_floor')";

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
        let (since, until, floor) = sqlx::query_as(READ_COVERAGE).fetch_one(executor).await?;
        Ok(Self {
            since,
            until,
            floor,
        })
    }
}

/// Column format of an hour boundary. Hours come from stored rows or the clock, so
/// they are always inside chrono's range.
fn hour_ts(unix_secs: i64) -> String {
    unix_cutoff(unix_secs).unwrap_or_default()
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

pub(super) async fn split_hours(
    pool: &SqlitePool,
    start: DateTime<Utc>,
) -> Result<HourSplit, sqlx::Error> {
    let coverage = Coverage::read(pool).await?;
    let cutoff_secs = start.timestamp();
    let from = ceil_bucket(cutoff_secs, HOUR_SECS).max(coverage.since);
    // Without a held hour inside the window, the whole window is a raw tail.
    let (from, until) = if from < coverage.until {
        (from, coverage.until)
    } else {
        (cutoff_secs, cutoff_secs)
    };
    let cutoff = sql_ts(start);
    Ok(HourSplit {
        lead_end: unix_cutoff(from).unwrap_or_else(|| cutoff.clone()),
        tail_start: unix_cutoff(until).unwrap_or_else(|| cutoff.clone()),
        cutoff,
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
        let Some(hour) = next_hour(read_pool, coverage).await? else {
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

async fn next_hour(pool: &SqlitePool, coverage: Coverage) -> Result<Option<i64>, sqlx::Error> {
    let closed_before = hour_bucket(Utc::now().timestamp() - CLOSE_LAG_SECS);
    if coverage.until < closed_before {
        return Ok(Some(coverage.until));
    }
    let oldest: Option<i64> = sqlx::query_scalar(
        "SELECT CAST(strftime('%s', MIN(created_at)) AS INTEGER)
         FROM query_log WHERE query_source = 'client'",
    )
    .fetch_one(pool)
    .await?;
    let previous = coverage.since - HOUR_SECS;
    Ok(oldest
        .filter(|&oldest| previous >= hour_bucket(oldest).max(coverage.floor))
        .map(|_| previous))
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
    .bind(hour_ts(hour))
    .bind(hour_ts(hour + HOUR_SECS))
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
    // IMMEDIATE takes the write lock up front, so a busy writer is waited out. A
    // deferred transaction that reads first cannot wait when it upgrades: it fails.
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    if Coverage::read(&mut *tx).await? != picked_from {
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
    let (name, value) = if hour == picked_from.until {
        ("hour_until", hour + HOUR_SECS)
    } else {
        ("hour_since", hour)
    };
    sqlx::query("UPDATE query_log_rollup_state SET value = ? WHERE name = ?")
        .bind(value)
        .bind(name)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}
