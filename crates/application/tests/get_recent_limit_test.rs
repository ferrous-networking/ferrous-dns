use async_trait::async_trait;
use ferrous_dns_application::ports::{
    CacheStats, PagedQueryResult, QueryLogRepository, TimeGranularity, TimelineBucket,
};
use ferrous_dns_application::use_cases::{GetRecentQueriesUseCase, PagedQueryInput};
use ferrous_dns_domain::{query_log::QueryLog, DomainError, QueryLogFilter, QueryStats};
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
        _: &QueryLogFilter,
    ) -> Result<PagedQueryResult, DomainError> {
        *self.last_limit.lock().unwrap() = limit;
        Ok(PagedQueryResult {
            queries: vec![],
            records_total: 0,
            records_filtered: 0,
            next_cursor: None,
        })
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

    async fn get_top_allowed_domains(
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

    let input = PagedQueryInput {
        limit: 5_000,
        period_hours: 24.0,
        ..Default::default()
    };
    use_case.execute_paged(&input).await.unwrap();

    assert_eq!(*captured.lock().unwrap(), 1_000);
}

#[tokio::test]
async fn test_invalid_record_type_returns_error() {
    let captured = Arc::new(Mutex::new(0u32));
    let repo = Arc::new(CaptureLimitRepository {
        last_limit: captured.clone(),
    });
    let use_case = GetRecentQueriesUseCase::new(repo);

    let input = PagedQueryInput {
        limit: 100,
        period_hours: 24.0,
        record_type: Some("INVALID"),
        ..Default::default()
    };
    let result = use_case.execute_paged(&input).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DomainError::InvalidInput(_)));
}

#[tokio::test]
async fn test_invalid_client_ip_returns_error() {
    let captured = Arc::new(Mutex::new(0u32));
    let repo = Arc::new(CaptureLimitRepository {
        last_limit: captured.clone(),
    });
    let use_case = GetRecentQueriesUseCase::new(repo);

    let input = PagedQueryInput {
        limit: 100,
        period_hours: 24.0,
        client_ip: Some("not-an-ip"),
        ..Default::default()
    };
    let result = use_case.execute_paged(&input).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DomainError::InvalidInput(_)));
}

#[tokio::test]
async fn test_invalid_category_returns_error() {
    let captured = Arc::new(Mutex::new(0u32));
    let repo = Arc::new(CaptureLimitRepository {
        last_limit: captured.clone(),
    });
    let use_case = GetRecentQueriesUseCase::new(repo);

    let input = PagedQueryInput {
        limit: 100,
        period_hours: 24.0,
        category: Some("NONSENSE"),
        ..Default::default()
    };
    let result = use_case.execute_paged(&input).await;

    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), DomainError::InvalidInput(_)));
}
