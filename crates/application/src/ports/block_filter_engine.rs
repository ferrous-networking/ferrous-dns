use async_trait::async_trait;
use ferrous_dns_domain::{BlockSource, DomainError, FilterExplanation};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    Block(BlockSource),
    /// Not blocked, but no rule spoke for the domain either way.
    Allow,
    /// Allowed by a rule the operator wrote themselves — the allowlist, an
    /// allow-type managed domain or an allow regex filter.
    ///
    /// Callers that run their own heuristics on top of the filter (tunneling,
    /// DGA, rebinding, NXDOMAIN hijack, response-IP filtering) must skip them
    /// for these domains: an explicit allow is how the operator clears a false
    /// positive, and it would be pointless if a detector could override it.
    ExplicitAllow,
}

#[async_trait]
pub trait BlockFilterEnginePort: Send + Sync {
    fn resolve_group(&self, ip: IpAddr) -> i64;
    fn check(&self, domain: &str, group_id: i64) -> FilterDecision;
    /// Read-only, exhaustive attribution of how the static filter index evaluates
    /// `domain` for `group_id` (all matching allow/block rules, named). Does not
    /// touch any decision cache.
    ///
    /// The default returns an empty "not blocked" explanation; the real engine
    /// overrides it. Mock/no-op implementations can rely on the default.
    fn explain(&self, domain: &str, group_id: i64) -> FilterExplanation {
        FilterExplanation {
            domain: domain.to_string(),
            group_id,
            blocked: false,
            allow_reasons: Vec::new(),
            block_matches: Vec::new(),
        }
    }
    /// Batch variant of [`BlockFilterEnginePort::explain`]. Implementations may
    /// load the index snapshot once for the whole batch.
    fn explain_batch(&self, domains: &[String], group_id: i64) -> Vec<FilterExplanation> {
        domains.iter().map(|d| self.explain(d, group_id)).collect()
    }
    /// Evaluate which of `domains` match a candidate ruleset that is NOT
    /// (necessarily) applied to the live index — used by the what-if backtest.
    ///
    /// `list_lines` are raw blocklist-style lines (hosts/adblock/wildcard/plain,
    /// comments skipped) parsed exactly as real lists are; `regexes` are raw
    /// regex patterns. Returns one `bool` per input domain (`true` = matched).
    ///
    /// The default matches nothing (mocks rely on it); the real engine — which
    /// owns the list parser and regex compiler — overrides it. Errors only on an
    /// invalid regex pattern.
    fn match_candidate(
        &self,
        domains: &[String],
        list_lines: &[String],
        regexes: &[String],
    ) -> Result<Vec<bool>, DomainError> {
        let _ = (list_lines, regexes);
        Ok(vec![false; domains.len()])
    }
    fn store_cname_decision(&self, domain: &str, group_id: i64, ttl_secs: u64);
    async fn reload(&self) -> Result<(), DomainError>;
    async fn load_client_groups(&self) -> Result<(), DomainError>;
    fn compiled_domain_count(&self) -> usize;
    fn is_blocking_enabled(&self) -> bool;
    fn set_blocking_enabled(&self, enabled: bool);
}
