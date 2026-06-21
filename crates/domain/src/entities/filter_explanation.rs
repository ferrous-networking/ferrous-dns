use serde::{Deserialize, Serialize};

/// How a domain matched a rule in the static filter index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchType {
    /// Exact domain match.
    Exact,
    /// Wildcard (suffix) match.
    Wildcard,
    /// Substring / Aho-Corasick pattern match.
    Pattern,
    /// Regex match.
    Regex,
}

/// Category of a blocking rule that matched a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockMatchKind {
    /// A downloaded blocklist source.
    Blocklist,
    /// The global manual blocklist.
    Manual,
    /// A managed (custom) deny domain.
    ManagedDomain,
    /// A user-defined deny regex filter.
    Regex,
}

/// Category of an allow rule that matched a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowMatchKind {
    /// An allowlist (whitelist) entry — global or group scoped.
    Allowlist,
    /// A user-defined allow regex filter.
    Regex,
}

/// A single blocklist/regex/managed rule that would block the domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockMatch {
    pub kind: BlockMatchKind,
    /// Database id of the source/regex when known (`None` for the manual list).
    pub source_id: Option<i64>,
    /// Human-readable name of the matched source/rule.
    pub name: String,
    pub match_type: MatchType,
}

/// A single allow rule that would allow the domain (overrides blocking).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AllowMatch {
    pub kind: AllowMatchKind,
    /// Database id of the regex filter when applicable.
    pub source_id: Option<i64>,
    /// Human-readable description of the matched allow rule.
    pub name: String,
    pub match_type: MatchType,
}

/// Full attribution of how the static filter index evaluates a domain.
///
/// Reflects only the in-memory block index — downloaded blocklists, the manual
/// blocklist, managed domains, regex filters and allowlists. Dynamic runtime
/// rules (schedule, CNAME cloaking, DNS rebinding, rate-limit, tunneling) are
/// NOT represented here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterExplanation {
    pub domain: String,
    pub group_id: i64,
    /// Final verdict respecting allow-over-block precedence.
    pub blocked: bool,
    /// Allow rules that matched (any present => the domain is not blocked).
    pub allow_reasons: Vec<AllowMatch>,
    /// Blocking rules that matched (listed even when an allow rule overrides them).
    pub block_matches: Vec<BlockMatch>,
}
