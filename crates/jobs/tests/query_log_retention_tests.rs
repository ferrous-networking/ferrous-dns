use async_trait::async_trait;
use ferrous_dns_application::ports::{
    CacheStats, PagedQueryResult, QueryLogRepository, TimeGranularity, TimelineBucket,
};
use ferrous_dns_application::use_cases::CleanupOldQueryLogsUseCase;
use ferrous_dns_domain::{
    DnssecStats, DomainError, QueryLog, QueryLogFilter, QueryStats, RecordType,
};
use ferrous_dns_jobs::QueryLogRetentionJob;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration};

struct MockQueryLogRepository {
    logs: RwLock<Vec<(QueryLog, String)>>,
}

impl MockQueryLogRepository {
    fn new() -> Self {
        Self {
            logs: RwLock::new(Vec::new()),
        }
    }

    async fn count(&self) -> usize {
        self.logs.read().await.len()
    }

    async fn add_log_at(&self, ip: &str, timestamp: String) {
        let log = QueryLog {
            id: None,
            domain: "test.example.com".into(),
            record_type: RecordType::A,
            client_ip: ip.parse().unwrap(),
            client_hostname: None,
            blocked: false,
            response_time_us: Some(10),
            cache_hit: false,
            cache_refresh: false,
            dnssec_status: None,
            dns64_synthesized: false,
            answers: None,
            upstream_server: None,
            upstream_pool: None,
            response_status: None,
            timestamp: Some(timestamp.clone()),
            query_source: Default::default(),
            protocol: None,
            group_id: None,
            block_source: None,
        };
        self.logs.write().await.push((log, timestamp));
    }

    async fn add_recent_log(&self, ip: &str) {
        self.add_log_at(ip, chrono::Utc::now().to_rfc3339()).await;
    }

    async fn add_old_log(&self, ip: &str, days_old: i64) {
        let ts = (chrono::Utc::now() - chrono::Duration::days(days_old)).to_rfc3339();
        self.add_log_at(ip, ts).await;
    }
}

#[async_trait]
impl QueryLogRepository for MockQueryLogRepository {
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError> {
        let ts = chrono::Utc::now().to_rfc3339();
        self.logs.write().await.push((query.clone(), ts));
        Ok(())
    }

    fn log_query_sync(&self, _query: &QueryLog) -> Result<(), DomainError> {
        unimplemented!()
    }

    async fn get_recent(
        &self,
        limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        let logs = self.logs.read().await;
        let start = logs.len().saturating_sub(limit as usize);
        Ok(logs[start..].iter().map(|(l, _)| l.clone()).collect())
    }

    async fn get_recent_paged(
        &self,
        limit: u32,
        page: ferrous_dns_application::ports::PageAt,
        period_hours: f32,
        _filter: &QueryLogFilter,
    ) -> Result<PagedQueryResult, DomainError> {
        let ferrous_dns_application::ports::PageAt::Offset(offset) = page else {
            unimplemented!()
        };
        let all = self.get_recent(limit + offset, period_hours).await?;
        let total = all.len() as u64;
        let queries: Vec<QueryLog> = all
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect();
        Ok(PagedQueryResult {
            queries,
            records_total: total,
            records_filtered: total,
            next_cursor: None,
        })
    }

    async fn get_stats(&self, _period_hours: f32) -> Result<QueryStats, DomainError> {
        let logs = self.logs.read().await;
        Ok(QueryStats {
            queries_total: logs.len() as u64,
            queries_blocked: logs.iter().filter(|(l, _)| l.blocked).count() as u64,
            queries_rate_limited: 0,
            queries_malware_detected: 0,
            queries_dnssec_bogus: 0,
            queries_dns64_synthesized: 0,
            unique_clients: 0,
            uptime_seconds: 0,
            cache_hit_rate: 0.0,
            avg_query_time_ms: 0.0,
            avg_cache_time_ms: 0.0,
            avg_upstream_time_ms: 0.0,
            source_stats: HashMap::new(),
            queries_by_type: HashMap::new(),
            most_queried_type: None,
            record_type_distribution: Vec::new(),
        })
    }

    async fn get_dnssec_stats(&self, _period_hours: f32) -> Result<DnssecStats, DomainError> {
        Ok(DnssecStats::default())
    }

    async fn get_timeline(
        &self,
        _period_hours: f32,
        _granularity: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        Ok(Vec::new())
    }

    async fn count_queries_since(&self, _seconds_ago: i64) -> Result<u64, DomainError> {
        Ok(self.logs.read().await.len() as u64)
    }

    async fn get_cache_stats(&self, _period_hours: f32) -> Result<CacheStats, DomainError> {
        Ok(CacheStats {
            total_hits: 0,
            total_misses: 0,
            total_refreshes: 0,
            hit_rate: 0.0,
            refresh_rate: 0.0,
        })
    }

    async fn get_top_blocked_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        Ok(Vec::new())
    }

    async fn get_top_allowed_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        Ok(Vec::new())
    }

    async fn get_distinct_recent_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        Ok(Vec::new())
    }

    async fn count_distinct_domains(&self, _period_hours: f32) -> Result<u64, DomainError> {
        Ok(0)
    }

    async fn get_top_clients(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
        Ok(Vec::new())
    }

    async fn delete_older_than(&self, days: u32) -> Result<u64, DomainError> {
        let cutoff = (chrono::Utc::now() - chrono::Duration::days(days as i64)).to_rfc3339();
        let mut logs = self.logs.write().await;
        let before = logs.len();
        logs.retain(|(_, ts)| ts.as_str() >= cutoff.as_str());
        Ok((before - logs.len()) as u64)
    }
}

#[tokio::test(start_paused = true)]
async fn test_query_log_retention_job_removes_only_logs_past_configured_days() {
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_recent_log("10.0.0.1").await;
    repo.add_old_log("10.0.0.2", 3).await;
    repo.add_old_log("10.0.0.3", 10).await;

    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo.clone()));
    QueryLogRetentionJob::new(use_case, 7).spawn();
    sleep(FOUR_HOURS + Duration::from_secs(1)).await;

    assert_eq!(repo.count().await, 2);
}

#[tokio::test]
async fn test_query_log_retention_job_reruns_on_interval() {
    let repo = Arc::new(MockQueryLogRepository::new());
    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo.clone()));

    QueryLogRetentionJob::new(use_case, 7)
        .with_interval(1)
        .spawn();
    sleep(Duration::from_millis(200)).await;

    repo.add_old_log("10.0.0.1", 10).await;
    assert_eq!(repo.count().await, 1);

    sleep(Duration::from_millis(1100)).await;

    assert_eq!(repo.count().await, 0, "the second tick should clean up");
}

const FOUR_HOURS: Duration = Duration::from_secs(4 * 3600);

#[tokio::test(start_paused = true)]
async fn test_query_log_retention_job_skips_startup_and_first_runs_four_hours_later() {
    let repo = Arc::new(MockQueryLogRepository::new());
    repo.add_old_log("10.0.0.1", 10).await;

    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo.clone()));
    QueryLogRetentionJob::new(use_case, 7).spawn();

    sleep(FOUR_HOURS - Duration::from_secs(1)).await;
    assert_eq!(repo.count().await, 1, "no cleanup may compete with startup");

    sleep(Duration::from_secs(2)).await;
    assert_eq!(
        repo.count().await,
        0,
        "the first cleanup runs 4 hours after startup"
    );
}

#[tokio::test(start_paused = true)]
async fn test_query_log_retention_job_reruns_every_four_hours() {
    let repo = Arc::new(MockQueryLogRepository::new());
    let use_case = Arc::new(CleanupOldQueryLogsUseCase::new(repo.clone()));
    QueryLogRetentionJob::new(use_case, 7).spawn();

    sleep(FOUR_HOURS + Duration::from_secs(1)).await;
    repo.add_old_log("10.0.0.1", 10).await;

    sleep(FOUR_HOURS).await;
    assert_eq!(
        repo.count().await,
        0,
        "the cleanup repeats 4 hours after the previous one"
    );
}
