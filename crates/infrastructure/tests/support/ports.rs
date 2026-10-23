//! Port doubles for driving `HandleDnsQueryUseCase` through the DNS server
//! handler. Only the resolution path is exercised; unused trait methods panic.
#![allow(dead_code)]

use async_trait::async_trait;
use ferrous_dns_application::ports::{
    BlockFilterEnginePort, CacheStats, FilterDecision, PagedQueryResult, QueryLogRepository,
    TimeGranularity, TimelineBucket,
};
use ferrous_dns_domain::{DnssecStats, DomainError, QueryLog, QueryLogFilter, QueryStats};
use std::net::IpAddr;
use std::sync::Mutex;

/// Allows every domain; assigns the default group.
pub struct AllowAllFilter;

#[async_trait]
impl BlockFilterEnginePort for AllowAllFilter {
    fn resolve_group(&self, _ip: IpAddr) -> i64 {
        0
    }
    fn check(&self, _domain: &str, _group_id: i64) -> FilterDecision {
        FilterDecision::Allow
    }
    fn explain(&self, _domain: &str, _group_id: i64) -> ferrous_dns_domain::FilterExplanation {
        unimplemented!()
    }
    fn match_candidate(
        &self,
        _domains: &[String],
        _list_lines: &[String],
        _regexes: &[String],
    ) -> Result<Vec<bool>, DomainError> {
        unimplemented!()
    }
    fn store_cname_decision(&self, _domain: &str, _group_id: i64, _ttl_secs: u64) {}
    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }
    async fn load_client_groups(&self) -> Result<(), DomainError> {
        Ok(())
    }
    fn compiled_domain_count(&self) -> usize {
        0
    }
    fn is_blocking_enabled(&self) -> bool {
        false
    }
    fn set_blocking_enabled(&self, _enabled: bool) {}
}

/// Drops every logged query.
pub struct NoopQueryLog;

#[async_trait]
impl QueryLogRepository for NoopQueryLog {
    async fn log_query(&self, _query: &QueryLog) -> Result<(), DomainError> {
        Ok(())
    }
    fn log_query_sync(&self, _query: &QueryLog) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_recent(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        unimplemented!()
    }
    async fn get_recent_paged(
        &self,
        _limit: u32,
        _page: ferrous_dns_application::ports::PageAt,
        _period_hours: f32,
        _filter: &QueryLogFilter,
    ) -> Result<PagedQueryResult, DomainError> {
        unimplemented!()
    }
    async fn get_stats(&self, _period_hours: f32) -> Result<QueryStats, DomainError> {
        unimplemented!()
    }
    async fn get_dnssec_stats(&self, _period_hours: f32) -> Result<DnssecStats, DomainError> {
        unimplemented!()
    }
    async fn get_timeline(
        &self,
        _period_hours: f32,
        _granularity: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        unimplemented!()
    }
    async fn count_queries_since(&self, _seconds_ago: i64) -> Result<u64, DomainError> {
        unimplemented!()
    }
    async fn get_cache_stats(&self, _period_hours: f32) -> Result<CacheStats, DomainError> {
        unimplemented!()
    }
    async fn get_top_blocked_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn get_top_allowed_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn get_distinct_recent_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn count_distinct_domains(&self, _period_hours: f32) -> Result<u64, DomainError> {
        unimplemented!()
    }
    async fn get_top_clients(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
        unimplemented!()
    }
    async fn delete_older_than(&self, _days: u32) -> Result<u64, DomainError> {
        unimplemented!()
    }
}

/// Keeps every logged query, for a test that reads back what was logged.
#[derive(Default)]
pub struct RecordingQueryLog(Mutex<Vec<QueryLog>>);

impl RecordingQueryLog {
    pub fn logged(&self) -> Vec<QueryLog> {
        self.0.lock().unwrap().clone()
    }
}

#[async_trait]
impl QueryLogRepository for RecordingQueryLog {
    async fn log_query(&self, query: &QueryLog) -> Result<(), DomainError> {
        self.0.lock().unwrap().push(query.clone());
        Ok(())
    }
    fn log_query_sync(&self, query: &QueryLog) -> Result<(), DomainError> {
        self.0.lock().unwrap().push(query.clone());
        Ok(())
    }
    async fn get_recent(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<QueryLog>, DomainError> {
        unimplemented!()
    }
    async fn get_recent_paged(
        &self,
        _limit: u32,
        _page: ferrous_dns_application::ports::PageAt,
        _period_hours: f32,
        _filter: &QueryLogFilter,
    ) -> Result<PagedQueryResult, DomainError> {
        unimplemented!()
    }
    async fn get_stats(&self, _period_hours: f32) -> Result<QueryStats, DomainError> {
        unimplemented!()
    }
    async fn get_dnssec_stats(&self, _period_hours: f32) -> Result<DnssecStats, DomainError> {
        unimplemented!()
    }
    async fn get_timeline(
        &self,
        _period_hours: f32,
        _granularity: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        unimplemented!()
    }
    async fn count_queries_since(&self, _seconds_ago: i64) -> Result<u64, DomainError> {
        unimplemented!()
    }
    async fn get_cache_stats(&self, _period_hours: f32) -> Result<CacheStats, DomainError> {
        unimplemented!()
    }
    async fn get_top_blocked_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn get_top_allowed_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn get_distinct_recent_domains(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        unimplemented!()
    }
    async fn count_distinct_domains(&self, _period_hours: f32) -> Result<u64, DomainError> {
        unimplemented!()
    }
    async fn get_top_clients(
        &self,
        _limit: u32,
        _period_hours: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
        unimplemented!()
    }
    async fn delete_older_than(&self, _days: u32) -> Result<u64, DomainError> {
        unimplemented!()
    }
}
