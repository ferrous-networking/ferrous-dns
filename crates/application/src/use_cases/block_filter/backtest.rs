use crate::ports::{BlockFilterEnginePort, QueryLogRepository};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;

/// Default corpus size when the caller does not specify one.
pub const DEFAULT_BACKTEST_LIMIT: u32 = 20_000;
/// Hard cap on corpus size to bound work and response size.
pub const MAX_BACKTEST_LIMIT: u32 = 50_000;
/// Max number of affected domains returned as a sample.
pub const SAMPLE_LIMIT: usize = 100;

/// Which way the candidate ruleset is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateAction {
    /// Candidate is a blocklist: measure what it would newly block.
    Deny,
    /// Candidate is an allowlist: measure what it would newly free.
    Allow,
}

/// Request to simulate a candidate allow/deny ruleset (not yet applied) against
/// the domains seen in recent traffic.
pub struct BacktestRequest {
    pub action: CandidateAction,
    /// Raw pasted list lines (hosts/adblock/wildcard/plain; parsed in the engine).
    pub list_lines: Vec<String>,
    /// Raw regex patterns (fancy_regex).
    pub regexes: Vec<String>,
    /// Group context the corpus is evaluated against.
    pub group_id: i64,
    /// Lookback window in hours for the query-log corpus.
    pub window_hours: f32,
    /// Max corpus size (distinct domains, top by query count).
    pub limit: u32,
}

/// A single domain whose verdict the candidate would change.
#[derive(Debug, Clone)]
pub struct AffectedDomain {
    pub domain: String,
    pub queries: u64,
    /// For the allow action: the existing rule currently blocking this domain.
    pub blocked_by: Option<String>,
}

/// What-if impact of a candidate ruleset over the recent-traffic corpus.
#[derive(Debug, Clone)]
pub struct BacktestReport {
    pub group_id: i64,
    pub action: CandidateAction,
    pub window_hours: f32,
    /// Distinct domains evaluated.
    pub corpus_size: u64,
    /// Sum of query counts across the corpus.
    pub total_queries: u64,
    /// Distinct corpus domains currently blocked by the live (static) index.
    pub currently_blocked_domains: u64,
    pub currently_blocked_queries: u64,
    /// Distinct corpus domains the candidate matches (regardless of action).
    pub matched_domains: u64,
    pub matched_queries: u64,
    /// Domains whose verdict changes: newly blocked (deny) or newly freed (allow).
    pub changed_domains: u64,
    pub changed_queries: u64,
    /// Matched but no change: deny → already blocked; allow → already not blocked.
    pub redundant_domains: u64,
    pub redundant_queries: u64,
    /// Deny only: matched but an existing allow rule still wins (no effect).
    pub overridden_domains: u64,
    pub overridden_queries: u64,
    /// Up to `SAMPLE_LIMIT` changed domains, highest query count first.
    pub sample: Vec<AffectedDomain>,
}

/// Simulates a candidate allow/deny ruleset against recent traffic and reports
/// its marginal impact versus the current rules.
pub struct BacktestBlocklistsUseCase {
    engine: Arc<dyn BlockFilterEnginePort>,
    query_log: Arc<dyn QueryLogRepository>,
}

impl BacktestBlocklistsUseCase {
    pub fn new(
        engine: Arc<dyn BlockFilterEnginePort>,
        query_log: Arc<dyn QueryLogRepository>,
    ) -> Self {
        Self { engine, query_log }
    }

    pub async fn execute(&self, request: BacktestRequest) -> Result<BacktestReport, DomainError> {
        let BacktestRequest {
            action,
            list_lines,
            regexes,
            group_id,
            window_hours,
            limit,
        } = request;

        // Drop blank candidate lines (the engine parser handles the rest).
        let list_lines: Vec<String> = list_lines
            .into_iter()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        let regexes: Vec<String> = regexes
            .into_iter()
            .map(|r| r.trim().to_string())
            .filter(|r| !r.is_empty())
            .collect();

        let limit = limit.clamp(1, MAX_BACKTEST_LIMIT);
        let corpus = self
            .query_log
            .get_distinct_recent_domains(limit, window_hours)
            .await?;

        // Normalize the corpus to lowercase once so the candidate match and the
        // current-state explain agree on casing. Query-log domains are lowercased
        // at ingress, but normalizing here keeps a mixed-case corpus from skewing
        // the verdict (matching the candidate yet reading "not blocked").
        let domains: Vec<String> = corpus.iter().map(|(d, _)| d.to_ascii_lowercase()).collect();
        let matched = self
            .engine
            .match_candidate(&domains, &list_lines, &regexes)?;
        let current = self.engine.explain_batch(&domains, group_id);

        let mut report = BacktestReport {
            group_id,
            action,
            window_hours,
            corpus_size: 0,
            total_queries: 0,
            currently_blocked_domains: 0,
            currently_blocked_queries: 0,
            matched_domains: 0,
            matched_queries: 0,
            changed_domains: 0,
            changed_queries: 0,
            redundant_domains: 0,
            redundant_queries: 0,
            overridden_domains: 0,
            overridden_queries: 0,
            sample: Vec::new(),
        };

        for ((((_, count), domain), exp), &is_match) in corpus
            .iter()
            .zip(domains.iter())
            .zip(current.iter())
            .zip(matched.iter())
        {
            let count = *count;
            report.corpus_size += 1;
            report.total_queries += count;

            let was_blocked = exp.blocked;
            let current_allowed = !exp.allow_reasons.is_empty();
            if was_blocked {
                report.currently_blocked_domains += 1;
                report.currently_blocked_queries += count;
            }

            if !is_match {
                continue;
            }
            report.matched_domains += 1;
            report.matched_queries += count;

            match action {
                CandidateAction::Deny => {
                    if was_blocked {
                        report.redundant_domains += 1;
                        report.redundant_queries += count;
                    } else if current_allowed {
                        report.overridden_domains += 1;
                        report.overridden_queries += count;
                    } else {
                        report.changed_domains += 1;
                        report.changed_queries += count;
                        report.sample.push(AffectedDomain {
                            domain: domain.clone(),
                            queries: count,
                            blocked_by: None,
                        });
                    }
                }
                CandidateAction::Allow => {
                    if was_blocked {
                        report.changed_domains += 1;
                        report.changed_queries += count;
                        report.sample.push(AffectedDomain {
                            domain: domain.clone(),
                            queries: count,
                            blocked_by: exp.block_matches.first().map(|m| m.name.clone()),
                        });
                    } else {
                        report.redundant_domains += 1;
                        report.redundant_queries += count;
                    }
                }
            }
        }

        report
            .sample
            .sort_by(|a, b| b.queries.cmp(&a.queries).then(a.domain.cmp(&b.domain)));
        report.sample.truncate(SAMPLE_LIMIT);

        Ok(report)
    }
}
