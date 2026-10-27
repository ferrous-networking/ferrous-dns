//! Per-minute aggregates kept beside the raw `query_log` rows. Schema and the SQL
//! reference definitions live in the `*_query_log_rollups` migrations; the hourly
//! ones are in `hour_rollup`.

use super::writer::QueryLogEntry;
use crate::repositories::unix_cutoff;
use ferrous_dns_domain::{BlockSource, DnssecStatus, QuerySource, RecordType};
use sqlx::query::Query;
use sqlx::sqlite::{Sqlite, SqliteArguments, SqliteConnection};
use sqlx::{Executor, SqlitePool};
use std::sync::Arc;

type SqliteQuery<'q> = Query<'q, Sqlite, SqliteArguments<'q>>;

pub(super) const MINUTE_SECS: i64 = 60;
pub(super) const HOUR_SECS: i64 = 3_600;

/// Start of the minute containing `unix_secs`.
pub(super) fn minute_bucket(unix_secs: i64) -> i64 {
    unix_secs - unix_secs.rem_euclid(MINUTE_SECS)
}

/// Start of the hour containing `unix_secs`.
pub(super) fn hour_bucket(unix_secs: i64) -> i64 {
    unix_secs - unix_secs.rem_euclid(HOUR_SECS)
}

/// First bucket of `size` seconds that starts at or after `unix_secs`.
pub(super) fn ceil_bucket(unix_secs: i64, size: i64) -> i64 {
    unix_secs.saturating_add(size - 1).div_euclid(size) * size
}

/// Column format of a bucket boundary. Boundaries come from stored rows, the clock or
/// a window start, all inside chrono's range; one outside it is an error rather than a
/// silently empty range.
pub(super) fn bucket_ts(unix_secs: i64) -> Result<String, sqlx::Error> {
    unix_cutoff(unix_secs)
        .ok_or_else(|| sqlx::Error::Protocol(format!("bucket {unix_secs} is outside the calendar")))
}

/// Where a read of the window starting at `cutoff_secs` switches to the minute
/// rollups: the first bucket inside the window that they hold completely. Raw rows
/// cover the window before it, so raw part plus buckets equals the raw window.
pub(super) async fn first_complete_minute<'e, E>(
    executor: E,
    cutoff_secs: i64,
) -> Result<i64, sqlx::Error>
where
    E: Executor<'e, Database = Sqlite>,
{
    let since: i64 = sqlx::query_scalar("SELECT minute_since FROM query_log_rollup_state")
        .fetch_one(executor)
        .await?;
    Ok(ceil_bucket(cutoff_secs, MINUTE_SECS).max(since))
}

// One list drives the struct, the column list, the upsert's SET clause and the
// bind order, so a counter cannot be added to one and silently missed elsewhere.
macro_rules! minute_counters {
    (@placeholder $_field:ident) => {
        ", ?"
    };
    ($first:ident $(, $rest:ident)* $(,)?) => {
        /// Counters of one `query_log_minute` row; declaration order is column order.
        #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
        pub(super) struct MinuteCounters {
            pub $first: i64,
            $(pub $rest: i64,)*
        }

        const UPSERT_MINUTE: &str = concat!(
            "INSERT INTO query_log_minute (bucket, query_source, ",
            stringify!($first), $(", ", stringify!($rest),)*
            ") VALUES (?, ?, ?", $(minute_counters!(@placeholder $rest),)*
            ") ON CONFLICT (bucket, query_source) DO UPDATE SET ",
            stringify!($first), " = ", stringify!($first), " + excluded.", stringify!($first),
            $(", ", stringify!($rest), " = ", stringify!($rest), " + excluded.", stringify!($rest),)*
        );

        impl MinuteCounters {
            fn bind_counters<'q>(&self, q: SqliteQuery<'q>) -> SqliteQuery<'q> {
                q.bind(self.$first)$(.bind(self.$rest))*
            }
        }
    };
}

minute_counters!(
    total,
    blocked,
    cache_hits,
    cache_refreshes,
    cache_misses,
    local_dns,
    rate_limited,
    malware,
    dns64_synthesized,
    dnssec_validated,
    dnssec_secure,
    dnssec_insecure,
    dnssec_bogus,
    dnssec_indeterminate,
    timed,
    response_us_sum,
    cache_timed,
    cache_response_us_sum,
    upstream_timed,
    upstream_response_us_sum,
);

const UPSERT_RECORD_TYPE: &str = "INSERT INTO query_log_minute_record_type \
    (bucket, record_type, count) VALUES (?, ?, ?) \
    ON CONFLICT (bucket, record_type) DO UPDATE SET count = count + excluded.count";

const UPSERT_BLOCK_SOURCE: &str = "INSERT INTO query_log_minute_block_source \
    (bucket, block_source, count) VALUES (?, ?, ?) \
    ON CONFLICT (bucket, block_source) DO UPDATE SET count = count + excluded.count";

const UPSERT_UPSTREAM: &str = "INSERT INTO query_log_minute_upstream \
    (bucket, upstream_pool, upstream_server, count) VALUES (?, ?, ?, ?) \
    ON CONFLICT (bucket, upstream_pool, upstream_server) DO UPDATE SET count = count + excluded.count";

/// Answered by an upstream: not served from cache, not blocked, not a local record.
fn is_upstream(e: &QueryLogEntry) -> bool {
    !e.cache_hit && !e.blocked && e.response_status != Some("LOCAL_DNS")
}

impl MinuteCounters {
    fn add(&mut self, e: &QueryLogEntry) {
        let upstream = is_upstream(e);
        self.total += 1;
        self.blocked += i64::from(e.blocked);
        self.cache_hits += i64::from(e.cache_hit);
        self.cache_refreshes += i64::from(e.cache_refresh);
        self.cache_misses += i64::from(!e.cache_hit && !e.cache_refresh && !e.blocked);
        self.local_dns += i64::from(e.response_status == Some("LOCAL_DNS"));
        self.rate_limited += i64::from(matches!(
            e.response_status,
            Some("RATE_LIMITED" | "RATE_LIMITED_TC")
        ));
        self.malware += i64::from(e.blocked && e.block_source.is_some_and(BlockSource::is_malware));
        self.dns64_synthesized += i64::from(e.dns64_synthesized);
        if let Some(status) = e.dnssec_status {
            self.dnssec_validated += 1;
            match status {
                DnssecStatus::Secure => self.dnssec_secure += 1,
                DnssecStatus::Insecure => self.dnssec_insecure += 1,
                DnssecStatus::Bogus => self.dnssec_bogus += 1,
                DnssecStatus::Indeterminate => self.dnssec_indeterminate += 1,
            }
        }
        if let Some(us) = e.response_time_us {
            self.timed += 1;
            self.response_us_sum += us;
            if e.cache_hit {
                self.cache_timed += 1;
                self.cache_response_us_sum += us;
            }
            if upstream {
                self.upstream_timed += 1;
                self.upstream_response_us_sum += us;
            }
        }
    }
}

/// Aggregate of one flush. A flush stamps every row with the same time, so the
/// whole batch lands in one bucket and the keys here omit it. Key sets are a
/// handful of entries, so linear scans beat hashing.
#[derive(Debug, Default)]
pub(super) struct MinuteRollup {
    by_source: Vec<(QuerySource, MinuteCounters)>,
    record_types: Vec<(RecordType, i64)>,
    block_sources: Vec<(BlockSource, i64)>,
    upstreams: Vec<(UpstreamKey, i64)>,
}

/// `(upstream_pool, upstream_server)` as logged.
type UpstreamKey = (Option<Arc<str>>, Option<Arc<str>>);

fn bump<K: PartialEq>(counts: &mut Vec<(K, i64)>, key: K) {
    match counts.iter_mut().find(|(k, _)| *k == key) {
        Some((_, n)) => *n += 1,
        None => counts.push((key, 1)),
    }
}

impl MinuteRollup {
    pub fn add(&mut self, e: &QueryLogEntry) {
        let i = match self
            .by_source
            .iter()
            .position(|(s, _)| *s == e.query_source)
        {
            Some(i) => i,
            None => {
                self.by_source
                    .push((e.query_source, MinuteCounters::default()));
                self.by_source.len() - 1
            }
        };
        self.by_source[i].1.add(e);

        if e.query_source != QuerySource::Client {
            return;
        }
        bump(&mut self.record_types, e.record_type);
        if e.blocked {
            if let Some(source) = e.block_source {
                bump(&mut self.block_sources, source);
            }
        }
        if is_upstream(e) {
            bump(
                &mut self.upstreams,
                (e.upstream_pool.clone(), e.upstream_server.clone()),
            );
        }
    }

    pub async fn persist(
        &self,
        conn: &mut SqliteConnection,
        bucket: i64,
    ) -> Result<(), sqlx::Error> {
        for (source, counters) in &self.by_source {
            let q = sqlx::query(UPSERT_MINUTE)
                .bind(bucket)
                .bind(source.as_str());
            counters.bind_counters(q).execute(&mut *conn).await?;
        }
        for (record_type, count) in &self.record_types {
            sqlx::query(UPSERT_RECORD_TYPE)
                .bind(bucket)
                .bind(record_type.as_str())
                .bind(count)
                .execute(&mut *conn)
                .await?;
        }
        for (source, count) in &self.block_sources {
            sqlx::query(UPSERT_BLOCK_SOURCE)
                .bind(bucket)
                .bind(source.to_str())
                .bind(count)
                .execute(&mut *conn)
                .await?;
        }
        for ((pool, server), count) in &self.upstreams {
            sqlx::query(UPSERT_UPSTREAM)
                .bind(bucket)
                .bind(pool.as_deref().unwrap_or(""))
                .bind(server.as_deref().unwrap_or(""))
                .bind(count)
                .execute(&mut *conn)
                .await?;
        }
        Ok(())
    }
}

/// Drops every bucket that starts before `unix_secs`, in one transaction so the
/// tables never disagree about the retained range. A bucket straddling the cutoff
/// goes whole while its newer raw rows stay, so the coverage in
/// `query_log_rollup_state` moves past it, and the hourly job never refills an
/// hour before it.
pub(super) async fn prune_before(pool: &SqlitePool, unix_secs: i64) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    for sql in [
        "DELETE FROM query_log_minute WHERE bucket < ?",
        "DELETE FROM query_log_minute_record_type WHERE bucket < ?",
        "DELETE FROM query_log_minute_block_source WHERE bucket < ?",
        "DELETE FROM query_log_minute_upstream WHERE bucket < ?",
        "DELETE FROM query_log_hour_domain WHERE bucket < ?",
        "DELETE FROM query_log_hour_client WHERE bucket < ?",
    ] {
        sqlx::query(sql).bind(unix_secs).execute(&mut *tx).await?;
    }
    // Raising the three hour bounds to the same value keeps since >= floor and
    // until >= since.
    sqlx::query(
        "UPDATE query_log_rollup_state SET
             minute_since = MAX(minute_since, ?1),
             hour_since = MAX(hour_since, ?2),
             hour_until = MAX(hour_until, ?2),
             hour_floor = MAX(hour_floor, ?2)",
    )
    .bind(ceil_bucket(unix_secs, MINUTE_SECS))
    .bind(ceil_bucket(unix_secs, HOUR_SECS))
    .execute(&mut *tx)
    .await?;
    tx.commit().await
}

#[cfg(test)]
mod tests {
    use super::{ceil_bucket, HOUR_SECS};

    #[test]
    fn ceil_bucket_keeps_a_boundary_and_rounds_anything_else_up() {
        assert_eq!(ceil_bucket(7_200, HOUR_SECS), 7_200);
        assert_eq!(ceil_bucket(7_201, HOUR_SECS), 10_800);
        assert_eq!(ceil_bucket(-1, HOUR_SECS), 0);
        assert_eq!(
            ceil_bucket(i64::MIN, HOUR_SECS),
            i64::MIN / HOUR_SECS * HOUR_SECS
        );
    }
}
