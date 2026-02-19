use serde::{Deserialize, Serialize};

/// Identifies which filtering layer caused a DNS query to be blocked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockSource {
    /// Domain matched an entry from an external blocklist source
    /// (exact match, wildcard, or Aho-Corasick pattern).
    Blocklist,
    /// Domain matched a user-defined managed domain deny rule.
    ManagedDomain,
    /// Domain matched a user-defined regex filter deny rule.
    RegexFilter,
}

impl BlockSource {
    pub fn to_str(&self) -> &'static str {
        match self {
            BlockSource::Blocklist => "blocklist",
            BlockSource::ManagedDomain => "managed_domain",
            BlockSource::RegexFilter => "regex_filter",
        }
    }

    /// Convert from the u8 representation used in the decision cache.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(BlockSource::Blocklist),
            1 => Some(BlockSource::ManagedDomain),
            2 => Some(BlockSource::RegexFilter),
            _ => None,
        }
    }

    /// Convert to the u8 representation used in the decision cache.
    pub fn as_u8(&self) -> u8 {
        match self {
            BlockSource::Blocklist => 0,
            BlockSource::ManagedDomain => 1,
            BlockSource::RegexFilter => 2,
        }
    }
}

impl std::fmt::Display for BlockSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}
