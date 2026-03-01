mod helpers;
mod reader;
mod timeline;
mod writer;

use async_trait::async_trait;
use ferrous_dns_application::ports::{QueryLogRepository, TimeGranularity, TimelineBucket};
use ferrous_dns_domain::{config::DatabaseConfig, DomainError, QueryLog, QueryStats};
use sqlx::SqlitePool;
use std::sync::atomic::{AtomicU64, Ordering};
use timeline::TimelineCache;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use writer::QueryLogEntry;

pub struct SqliteQueryLogRepository {
    write_pool: SqlitePool,
    read_pool: SqlitePool,
    sender: mpsc::Sender<QueryLogEntry>,
    sample_rate: u32,
    sample_counter: AtomicU64,
    timeline_cache: TimelineCache,
}

impl SqliteQueryLogRepository {
    pub fn new(
        write_pool: SqlitePool,
        query_log_pool: SqlitePool,
        read_pool: SqlitePool,
        cfg: &DatabaseConfig,
    ) -> Self {
        let channel_capacity = cfg.query_log_channel_capacity;
        let max_batch_size = cfg.query_log_max_batch_size;
        let flush_interval_ms = cfg.query_log_flush_interval_ms;

        let (sender, receiver) = mpsc::channel(channel_capacity);

        tokio::spawn(async move {
            writer::flush_loop(query_log_pool, receiver, max_batch_size, flush_interval_ms).await;
        });

        info!(
            channel_capacity,
            batch_size = max_batch_size,
            flush_interval_ms,
            sample_rate = cfg.query_log_sample_rate,
            "Query log batching enabled"
        );

        Self {
            write_pool,
            read_pool,
            sender,
            sample_rate: cfg.query_log_sample_rate,
            sample_counter: AtomicU64::new(0),
            timeline_cache: TimelineCache::new(),
        }
    }
}

#[async_trait]
impl QueryLogRepository for SqliteQueryLogRepository {
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError> {
        self.log_query_sync(query)
    }

    fn log_query_sync(&self, query: &QueryLog) -> Result<(), DomainError> {
        if self.sample_rate > 1 {
            let n = self.sample_counter.fetch_add(1, Ordering::Relaxed);
            if !n.is_multiple_of(self.sample_rate as u64) {
                return Ok(());
            }
        }

        let entry = QueryLogEntry::from_query_log(query);
        match self.sender.try_send(entry) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!("Query log channel full, dropping entry");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                error!("Query log channel closed");
                Ok(())
            }
        }
    }

    async fn get_recent(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        reader::get_recent(&self.read_pool, limit, period_hours).await
    }

    async fn get_recent_paged(
        &self,
        limit: u32,
        offset: u32,
        period_hours: f32,
        cursor: Option<i64>,
    ) -> Result<(Vec<QueryLog>, u64, Option<i64>), DomainError> {
        reader::get_recent_paged(&self.read_pool, limit, offset, period_hours, cursor).await
    }

    async fn get_stats(&self, period_hours: f32) -> Result<QueryStats, DomainError> {
        reader::get_stats(&self.read_pool, period_hours).await
    }

    async fn get_timeline(
        &self,
        period_hours: u32,
        granularity: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        timeline::get_timeline(
            &self.read_pool,
            &self.timeline_cache,
            period_hours,
            granularity,
        )
        .await
    }

    async fn count_queries_since(&self, seconds_ago: i64) -> Result<u64, DomainError> {
        reader::count_queries_since(&self.read_pool, seconds_ago).await
    }

    async fn get_cache_stats(
        &self,
        period_hours: f32,
    ) -> Result<ferrous_dns_application::ports::CacheStats, DomainError> {
        reader::get_cache_stats(&self.read_pool, period_hours).await
    }

    async fn get_top_blocked_domains(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        reader::get_top_blocked_domains(&self.read_pool, limit, period_hours).await
    }

    async fn get_top_clients(
        &self,
        limit: u32,
        period_hours: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
        reader::get_top_clients(&self.read_pool, limit, period_hours).await
    }

    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError> {
        reader::delete_older_than(&self.write_pool, days).await
    }
}
