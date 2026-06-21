use ferrous_dns_application::use_cases::{AffectedDomain, BacktestReport, CandidateAction};
use ferrous_dns_domain::{
    AllowMatch, AllowMatchKind, BlockMatch, BlockMatchKind, FilterExplanation, MatchType,
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct BlockFilterStatsResponse {
    pub total_blocked_domains: usize,
}

// --- Single-domain test ---------------------------------------------------

/// Request to evaluate one domain against the static filter index.
#[derive(Deserialize, Debug, Clone, ToSchema)]
pub struct FilterTestRequest {
    pub domain: String,
    /// Optional client IP used to resolve the group when `group_id` is absent.
    #[serde(default)]
    pub client: Option<String>,
    /// Optional explicit group context (takes precedence over `client`).
    #[serde(default)]
    pub group_id: Option<i64>,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct FilterMatchDto {
    /// blocklist | manual | managed_domain | regex | allowlist
    pub kind: String,
    pub source_id: Option<i64>,
    pub name: String,
    /// exact | wildcard | pattern | regex
    pub match_type: String,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct FilterTestResponse {
    pub domain: String,
    pub group_id: i64,
    pub blocked: bool,
    /// Allow rules that matched (any present => not blocked).
    pub allow_reasons: Vec<FilterMatchDto>,
    /// Blocking rules that matched (listed even when an allow rule overrides them).
    pub block_matches: Vec<FilterMatchDto>,
}

fn block_kind_str(kind: BlockMatchKind) -> &'static str {
    match kind {
        BlockMatchKind::Blocklist => "blocklist",
        BlockMatchKind::Manual => "manual",
        BlockMatchKind::ManagedDomain => "managed_domain",
        BlockMatchKind::Regex => "regex",
    }
}

fn allow_kind_str(kind: AllowMatchKind) -> &'static str {
    match kind {
        AllowMatchKind::Allowlist => "allowlist",
        AllowMatchKind::Regex => "regex",
    }
}

fn match_type_str(match_type: MatchType) -> &'static str {
    match match_type {
        MatchType::Exact => "exact",
        MatchType::Wildcard => "wildcard",
        MatchType::Pattern => "pattern",
        MatchType::Regex => "regex",
    }
}

impl From<&BlockMatch> for FilterMatchDto {
    fn from(m: &BlockMatch) -> Self {
        Self {
            kind: block_kind_str(m.kind).to_string(),
            source_id: m.source_id,
            name: m.name.clone(),
            match_type: match_type_str(m.match_type).to_string(),
        }
    }
}

impl From<&AllowMatch> for FilterMatchDto {
    fn from(m: &AllowMatch) -> Self {
        Self {
            kind: allow_kind_str(m.kind).to_string(),
            source_id: m.source_id,
            name: m.name.clone(),
            match_type: match_type_str(m.match_type).to_string(),
        }
    }
}

impl From<FilterExplanation> for FilterTestResponse {
    fn from(e: FilterExplanation) -> Self {
        Self {
            domain: e.domain,
            group_id: e.group_id,
            blocked: e.blocked,
            allow_reasons: e.allow_reasons.iter().map(FilterMatchDto::from).collect(),
            block_matches: e.block_matches.iter().map(FilterMatchDto::from).collect(),
        }
    }
}

// --- Backtest (what-if simulator) -----------------------------------------

/// Request to simulate a candidate allow/deny ruleset (not yet applied) over the
/// domains seen in recent traffic.
#[derive(Deserialize, Debug, Clone, ToSchema)]
pub struct BacktestRequestDto {
    /// "deny" (candidate blocklist) or "allow" (candidate allowlist).
    pub action: String,
    /// Raw pasted list lines (hosts/adblock/wildcard/plain; comments skipped).
    #[serde(default)]
    pub list: Vec<String>,
    /// Raw regex patterns.
    #[serde(default)]
    pub regexes: Vec<String>,
    /// Group context the corpus is evaluated against (default 1).
    #[serde(default)]
    pub group_id: Option<i64>,
    /// Lookback window in hours (default 24).
    #[serde(default)]
    pub window_hours: Option<f32>,
    /// Max corpus size (distinct domains, top by query count).
    #[serde(default)]
    pub limit: Option<u32>,
}

/// A single domain whose verdict the candidate would change.
#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct AffectedDomainDto {
    pub domain: String,
    pub queries: u64,
    /// For the allow action: the existing rule currently blocking this domain.
    pub blocked_by: Option<String>,
}

#[derive(Serialize, Debug, Clone, ToSchema)]
pub struct BacktestResponse {
    /// "deny" or "allow".
    pub action: String,
    pub group_id: i64,
    pub window_hours: f32,
    /// Distinct domains evaluated.
    pub corpus_size: u64,
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
    /// Up to 100 changed domains, highest query count first.
    pub sample: Vec<AffectedDomainDto>,
}

fn candidate_action_str(action: CandidateAction) -> &'static str {
    match action {
        CandidateAction::Deny => "deny",
        CandidateAction::Allow => "allow",
    }
}

impl From<AffectedDomain> for AffectedDomainDto {
    fn from(a: AffectedDomain) -> Self {
        Self {
            domain: a.domain,
            queries: a.queries,
            blocked_by: a.blocked_by,
        }
    }
}

impl From<BacktestReport> for BacktestResponse {
    fn from(r: BacktestReport) -> Self {
        Self {
            action: candidate_action_str(r.action).to_string(),
            group_id: r.group_id,
            window_hours: r.window_hours,
            corpus_size: r.corpus_size,
            total_queries: r.total_queries,
            currently_blocked_domains: r.currently_blocked_domains,
            currently_blocked_queries: r.currently_blocked_queries,
            matched_domains: r.matched_domains,
            matched_queries: r.matched_queries,
            changed_domains: r.changed_domains,
            changed_queries: r.changed_queries,
            redundant_domains: r.redundant_domains,
            redundant_queries: r.redundant_queries,
            overridden_domains: r.overridden_domains,
            overridden_queries: r.overridden_queries,
            sample: r.sample.into_iter().map(AffectedDomainDto::from).collect(),
        }
    }
}
