use ferrous_dns_api::dto::block_filter::{BacktestResponse, FilterTestResponse};
use ferrous_dns_application::use_cases::{AffectedDomain, BacktestReport, CandidateAction};
use ferrous_dns_domain::{
    AllowMatch, AllowMatchKind, BlockMatch, BlockMatchKind, FilterExplanation, MatchType,
};

#[test]
fn filter_test_response_maps_named_block_attribution() {
    let exp = FilterExplanation {
        domain: "ads.example.com".to_string(),
        group_id: 1,
        blocked: true,
        allow_reasons: vec![],
        block_matches: vec![BlockMatch {
            kind: BlockMatchKind::Blocklist,
            source_id: Some(10),
            name: "EasyList".to_string(),
            match_type: MatchType::Exact,
        }],
    };

    let dto = FilterTestResponse::from(exp);
    assert_eq!(dto.domain, "ads.example.com");
    assert_eq!(dto.group_id, 1);
    assert!(dto.blocked);
    assert_eq!(dto.block_matches.len(), 1);
    assert_eq!(dto.block_matches[0].kind, "blocklist");
    assert_eq!(dto.block_matches[0].match_type, "exact");
    assert_eq!(dto.block_matches[0].source_id, Some(10));
    assert_eq!(dto.block_matches[0].name, "EasyList");
}

#[test]
fn filter_test_response_maps_allow_reasons() {
    let exp = FilterExplanation {
        domain: "ok.example.com".to_string(),
        group_id: 2,
        blocked: false,
        allow_reasons: vec![AllowMatch {
            kind: AllowMatchKind::Regex,
            source_id: Some(3),
            name: "allow-cdn".to_string(),
            match_type: MatchType::Regex,
        }],
        block_matches: vec![],
    };

    let dto = FilterTestResponse::from(exp);
    assert!(!dto.blocked);
    assert_eq!(dto.allow_reasons.len(), 1);
    assert_eq!(dto.allow_reasons[0].kind, "regex");
    assert_eq!(dto.allow_reasons[0].match_type, "regex");
    assert_eq!(dto.allow_reasons[0].name, "allow-cdn");
}

#[test]
fn backtest_response_maps_whatif_report() {
    let report = BacktestReport {
        group_id: 1,
        action: CandidateAction::Allow,
        window_hours: 24.0,
        corpus_size: 100,
        total_queries: 500,
        currently_blocked_domains: 40,
        currently_blocked_queries: 220,
        matched_domains: 12,
        matched_queries: 90,
        changed_domains: 8,
        changed_queries: 70,
        redundant_domains: 4,
        redundant_queries: 20,
        overridden_domains: 0,
        overridden_queries: 0,
        sample: vec![AffectedDomain {
            domain: "cdn.example.com".to_string(),
            queries: 55,
            blocked_by: Some("EasyList".to_string()),
        }],
    };

    let dto = BacktestResponse::from(report);
    assert_eq!(dto.action, "allow");
    assert_eq!(dto.group_id, 1);
    assert_eq!(dto.window_hours, 24.0);
    assert_eq!(dto.corpus_size, 100);
    assert_eq!(dto.currently_blocked_domains, 40);
    assert_eq!(dto.matched_domains, 12);
    assert_eq!(dto.changed_domains, 8);
    assert_eq!(dto.changed_queries, 70);
    assert_eq!(dto.redundant_domains, 4);
    assert_eq!(dto.overridden_domains, 0);
    assert_eq!(dto.sample.len(), 1);
    assert_eq!(dto.sample[0].domain, "cdn.example.com");
    assert_eq!(dto.sample[0].queries, 55);
    assert_eq!(dto.sample[0].blocked_by.as_deref(), Some("EasyList"));
}
