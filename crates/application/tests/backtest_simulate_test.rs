use async_trait::async_trait;
use ferrous_dns_application::ports::{
    BlockFilterEnginePort, CacheStats, FilterDecision, PagedQueryResult, QueryLogRepository,
    TimeGranularity, TimelineBucket,
};
use ferrous_dns_application::use_cases::{
    BacktestBlocklistsUseCase, BacktestRequest, CandidateAction,
};
use ferrous_dns_domain::query_log::{QueryLog, QueryLogFilter, QueryStats};
use ferrous_dns_domain::{
    AllowMatch, AllowMatchKind, BlockMatch, BlockMatchKind, DomainError, FilterExplanation,
    MatchType,
};
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

/// Query log returning a fixed corpus for `get_distinct_recent_domains`.
struct FakeQueryLog {
    corpus: Vec<(String, u64)>,
}

#[async_trait]
impl QueryLogRepository for FakeQueryLog {
    async fn log_query(&self, _q: &QueryLog) -> Result<(), DomainError> {
        Ok(())
    }
    async fn get_recent(&self, _l: u32, _p: f32) -> Result<Vec<QueryLog>, DomainError> {
        Ok(Vec::new())
    }
    async fn get_recent_paged(
        &self,
        _l: u32,
        _o: u32,
        _p: f32,
        _c: Option<i64>,
        _f: &QueryLogFilter,
    ) -> Result<PagedQueryResult, DomainError> {
        unimplemented!()
    }
    async fn get_stats(&self, _p: f32) -> Result<QueryStats, DomainError> {
        unimplemented!()
    }
    async fn get_timeline(
        &self,
        _p: u32,
        _g: TimeGranularity,
    ) -> Result<Vec<TimelineBucket>, DomainError> {
        unimplemented!()
    }
    async fn count_queries_since(&self, _s: i64) -> Result<u64, DomainError> {
        Ok(0)
    }
    async fn get_cache_stats(&self, _p: f32) -> Result<CacheStats, DomainError> {
        unimplemented!()
    }
    async fn get_top_blocked_domains(
        &self,
        _l: u32,
        _p: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        Ok(Vec::new())
    }
    async fn get_top_allowed_domains(
        &self,
        _l: u32,
        _p: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        Ok(Vec::new())
    }
    async fn get_distinct_recent_domains(
        &self,
        _l: u32,
        _p: f32,
    ) -> Result<Vec<(String, u64)>, DomainError> {
        Ok(self.corpus.clone())
    }
    async fn get_top_clients(
        &self,
        _l: u32,
        _p: f32,
    ) -> Result<Vec<(String, Option<String>, u64)>, DomainError> {
        Ok(Vec::new())
    }
    async fn delete_older_than(&self, _d: u32) -> Result<u64, DomainError> {
        Ok(0)
    }
}

/// Engine whose currently-blocked / currently-allowed / candidate-matched
/// domains are fixed sets, so the use-case aggregation can be asserted exactly.
struct FakeEngine {
    blocked: HashSet<String>,
    allowed: HashSet<String>,
    candidate: HashSet<String>,
}

#[async_trait]
impl BlockFilterEnginePort for FakeEngine {
    fn resolve_group(&self, _ip: IpAddr) -> i64 {
        1
    }
    fn check(&self, _d: &str, _g: i64) -> FilterDecision {
        FilterDecision::Allow
    }
    fn explain(&self, domain: &str, group_id: i64) -> FilterExplanation {
        let allow_reasons = if self.allowed.contains(domain) {
            vec![AllowMatch {
                kind: AllowMatchKind::Allowlist,
                source_id: None,
                name: "TestAllow".to_string(),
                match_type: MatchType::Exact,
            }]
        } else {
            Vec::new()
        };
        let block_matches = if self.blocked.contains(domain) {
            vec![BlockMatch {
                kind: BlockMatchKind::Blocklist,
                source_id: Some(1),
                name: "TestList".to_string(),
                match_type: MatchType::Exact,
            }]
        } else {
            Vec::new()
        };
        let blocked = allow_reasons.is_empty() && !block_matches.is_empty();
        FilterExplanation {
            domain: domain.to_string(),
            group_id,
            blocked,
            allow_reasons,
            block_matches,
        }
    }
    fn match_candidate(
        &self,
        domains: &[String],
        _list: &[String],
        _re: &[String],
    ) -> Result<Vec<bool>, DomainError> {
        Ok(domains.iter().map(|d| self.candidate.contains(d)).collect())
    }
    fn store_cname_decision(&self, _d: &str, _g: i64, _t: u64) {}
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
        true
    }
    fn set_blocking_enabled(&self, _e: bool) {}
}

fn set(items: &[&str]) -> HashSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

fn use_case() -> BacktestBlocklistsUseCase {
    let query_log = Arc::new(FakeQueryLog {
        corpus: vec![
            ("new1.com".to_string(), 10),
            ("new2.com".to_string(), 5),
            ("already.com".to_string(), 8),
            ("allowedy.com".to_string(), 3),
            ("other.com".to_string(), 2),
            ("blk.com".to_string(), 4),
        ],
    });
    let engine = Arc::new(FakeEngine {
        blocked: set(&["already.com", "blk.com"]),
        allowed: set(&["allowedy.com"]),
        candidate: set(&["new1.com", "new2.com", "already.com", "allowedy.com"]),
    });
    BacktestBlocklistsUseCase::new(engine, query_log)
}

#[tokio::test]
async fn deny_reports_newly_blocked_redundant_and_overridden() {
    let report = use_case()
        .execute(BacktestRequest {
            action: CandidateAction::Deny,
            list_lines: vec!["ignored.example".to_string()],
            regexes: vec![],
            group_id: 1,
            window_hours: 24.0,
            limit: 1000,
        })
        .await
        .unwrap();

    assert_eq!(report.corpus_size, 6);
    assert_eq!(report.total_queries, 32);
    assert_eq!(report.currently_blocked_domains, 2);
    assert_eq!(report.currently_blocked_queries, 12);
    assert_eq!(report.matched_domains, 4);
    assert_eq!(report.matched_queries, 26);

    // newly blocked: new1 + new2
    assert_eq!(report.changed_domains, 2);
    assert_eq!(report.changed_queries, 15);
    // already.com matched but already blocked
    assert_eq!(report.redundant_domains, 1);
    assert_eq!(report.redundant_queries, 8);
    // allowedy.com matched but an allow rule still wins
    assert_eq!(report.overridden_domains, 1);
    assert_eq!(report.overridden_queries, 3);

    // sample = changed domains, highest query count first, no blocked_by for deny.
    assert_eq!(report.sample.len(), 2);
    assert_eq!(report.sample[0].domain, "new1.com");
    assert_eq!(report.sample[0].queries, 10);
    assert!(report.sample[0].blocked_by.is_none());
    assert_eq!(report.sample[1].domain, "new2.com");
}

#[tokio::test]
async fn allow_reports_freed_domains_with_blocked_by() {
    let report = use_case()
        .execute(BacktestRequest {
            action: CandidateAction::Allow,
            list_lines: vec!["ignored.example".to_string()],
            regexes: vec![],
            group_id: 1,
            window_hours: 24.0,
            limit: 1000,
        })
        .await
        .unwrap();

    assert_eq!(report.matched_domains, 4);
    // only already.com is currently blocked → freed
    assert_eq!(report.changed_domains, 1);
    assert_eq!(report.changed_queries, 8);
    // new1, new2, allowedy matched but were not blocked
    assert_eq!(report.redundant_domains, 3);
    assert_eq!(report.redundant_queries, 18);
    // allow never produces overridden
    assert_eq!(report.overridden_domains, 0);

    assert_eq!(report.sample.len(), 1);
    assert_eq!(report.sample[0].domain, "already.com");
    assert_eq!(report.sample[0].blocked_by.as_deref(), Some("TestList"));
}
