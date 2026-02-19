use ferrous_dns_application::ports::QueryLogRepository;
use ferrous_dns_application::use_cases::{GetQueryRateUseCase, RateUnit};
use ferrous_dns_domain::{QueryLog, QuerySource, RecordType};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

mod helpers;
use helpers::MockQueryLogRepository;

#[tokio::test]
async fn test_get_query_rate_empty_repository() {
    let repository_mock = Arc::new(MockQueryLogRepository::new());

    let use_case = GetQueryRateUseCase::new(
        repository_mock.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );

    let result = use_case.execute(RateUnit::Second).await;
    assert!(result.is_ok());

    let rate = result.unwrap();
    assert_eq!(rate.queries, 0);
    assert_eq!(rate.rate, "0 q/s");
}

#[tokio::test]
async fn test_get_query_rate_with_data() {
    let repository_mock = Arc::new(MockQueryLogRepository::new());

    for i in 0..150 {
        let query = QueryLog {
            id: None,
            domain: format!("example{}.com", i).into(),
            record_type: RecordType::A,
            client_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            blocked: false,
            response_time_ms: Some(10),
            cache_hit: false,
            cache_refresh: false,
            dnssec_status: None,
            upstream_server: Some("8.8.8.8".to_string()),
            response_status: None,
            timestamp: None,
            query_source: QuerySource::Client,
            group_id: None,
            block_source: None,
        };
        let _ = repository_mock.log_query(&query).await;
    }

    let use_case = GetQueryRateUseCase::new(
        repository_mock.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );

    let result = use_case.execute(RateUnit::Second).await;
    assert!(result.is_ok());

    let rate = result.unwrap();
    assert_eq!(rate.queries, 150);
    assert_eq!(rate.rate, "150 q/s");
}

#[tokio::test]
async fn test_get_query_rate_formatted_with_k() {
    let repository_mock = Arc::new(MockQueryLogRepository::new());

    for i in 0..1500 {
        let query = QueryLog {
            id: None,
            domain: format!("example{}.com", i).into(),
            record_type: RecordType::A,
            client_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            blocked: false,
            response_time_ms: Some(10),
            cache_hit: false,
            cache_refresh: false,
            dnssec_status: None,
            upstream_server: Some("8.8.8.8".to_string()),
            response_status: None,
            timestamp: None,
            query_source: QuerySource::Client,
            group_id: None,
            block_source: None,
        };
        let _ = repository_mock.log_query(&query).await;
    }

    let use_case = GetQueryRateUseCase::new(
        repository_mock.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );

    let result = use_case.execute(RateUnit::Second).await;
    assert!(result.is_ok());

    let rate = result.unwrap();
    assert_eq!(rate.queries, 1500);
    assert_eq!(rate.rate, "1.5k q/s");
}

#[tokio::test]
async fn test_get_query_rate_different_units() {
    let repository_mock = Arc::new(MockQueryLogRepository::new());

    for i in 0..9500 {
        let query = QueryLog {
            id: None,
            domain: format!("example{}.com", i % 1000).into(),
            record_type: RecordType::A,
            client_ip: IpAddr::from_str("192.168.1.1").unwrap(),
            blocked: i % 10 == 0,
            response_time_ms: Some(10),
            cache_hit: i % 3 == 0,
            cache_refresh: false,
            dnssec_status: None,
            upstream_server: Some("8.8.8.8".to_string()),
            response_status: None,
            timestamp: None,
            query_source: QuerySource::Client,
            group_id: None,
            block_source: None,
        };
        let _ = repository_mock.log_query(&query).await;
    }

    let use_case = GetQueryRateUseCase::new(
        repository_mock.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );

    let result_second = use_case.execute(RateUnit::Second).await.unwrap();
    assert_eq!(result_second.queries, 9500);
    assert_eq!(result_second.rate, "9.5k q/s");

    let result_minute = use_case.execute(RateUnit::Minute).await.unwrap();
    assert_eq!(result_minute.queries, 9500);
    assert_eq!(result_minute.rate, "9.5k q/m");

    let result_hour = use_case.execute(RateUnit::Hour).await.unwrap();
    assert_eq!(result_hour.queries, 9500);
    assert_eq!(result_hour.rate, "9.5k q/h");
}

#[tokio::test]
async fn test_rate_unit_conversion() {
    let repository_mock = Arc::new(MockQueryLogRepository::new());
    let use_case = GetQueryRateUseCase::new(
        repository_mock.clone() as Arc<dyn ferrous_dns_application::ports::QueryLogRepository>
    );

    let second_result = use_case.execute(RateUnit::Second).await.unwrap();
    assert!(second_result.rate.ends_with("q/s"));

    let minute_result = use_case.execute(RateUnit::Minute).await.unwrap();
    assert!(minute_result.rate.ends_with("q/m"));

    let hour_result = use_case.execute(RateUnit::Hour).await.unwrap();
    assert!(hour_result.rate.ends_with("q/h"));
}
