use async_trait::async_trait;
use ferrous_dns_application::ports::{
    CacheStats, QueryLogRepository, TimeGranularity, TimelineBucket,
};
use ferrous_dns_application::use_cases::GetRecentQueriesUseCase;
use ferrous_dns_domain::{query_log::QueryLog, DomainError, QueryStats};
use std::sync::{Arc, Mutex};

struct CaptureLimitRepository {
    last_limit: Arc<Mutex<u32>>,
}

#[async_trait]
impl QueryLogRepository for CaptureLimitRepository {
    async fn log_query(&self, _: &QueryLog) -> Result<(), DomainError> {
        Ok(())
    }

    async fn get_recent(&self, limit: u32, _: f32) -> Result<Vec<QueryLog>, DomainError> {
        *self.last_limit.lock().unwrap() = limit;
        Ok(vec![])
    }

    async fn get_recent_paged(
        &self,
        limit: u32,
        _: u32,
        _: f32,
        _: Option<i64>,
    ) -> Result<(Vec<QueryLog>, u64, Option<i64>), DomainError> {
        *self.last_limit.lock().unwrap() = limit;
        Ok((vec![], 0, None))
    }

    async fn get_stats(&self, _: f32) -> Result<QueryStats, DomainError> {
        unimplemented!()
    }

    async fn get_timeline(
        &self,
        _: u32,
        _: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        unimplemented!()
    }

    async fn count_queries_since(&self, _: i64) -> Result<u64, DomainError> {
        unimplemented!()
    }

    async fn get_cache_stats(&self, _: f32) -> Result<CacheStats, DomainError> {
        unimplemented!()
    }

    async fn get_top_blocked_domains(
        &self,
        _: u32,
        _: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }

    async fn get_top_clients(
        &self,
        _: u32,
        _: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
        unimplemented!()
    }

    async fn delete_older_than(&self, _: u32) -> Result<u64, DomainError> {
        unimplemented!()
    }
}

#[tokio::test]
async fn test_limit_above_max_is_capped() {
    let captured = Arc::new(Mutex::new(0u32));
    let repo = Arc::new(CaptureLimitRepository {
        last_limit: captured.clone(),
    });
    let use_case = GetRecentQueriesUseCase::new(repo);

    use_case.execute(99_999, 24.0).await.unwrap();

    assert_eq!(*captured.lock().unwrap(), 1_000);
}

#[tokio::test]
async fn test_limit_within_max_is_passed_through() {
    let captured = Arc::new(Mutex::new(0u32));
    let repo = Arc::new(CaptureLimitRepository {
        last_limit: captured.clone(),
    });
    let use_case = GetRecentQueriesUseCase::new(repo);

    use_case.execute(42, 24.0).await.unwrap();

    assert_eq!(*captured.lock().unwrap(), 42);
}

#[tokio::test]
async fn test_paged_limit_above_max_is_capped() {
    let captured = Arc::new(Mutex::new(0u32));
    let repo = Arc::new(CaptureLimitRepository {
        last_limit: captured.clone(),
    });
    let use_case = GetRecentQueriesUseCase::new(repo);

    use_case.execute_paged(5_000, 0, 24.0, None).await.unwrap();

    assert_eq!(*captured.lock().unwrap(), 1_000);
}
