use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockSource {
    Blocklist,
    ManagedDomain,
    RegexFilter,
    CnameCloaking,
    /// Blocked by a time-based schedule rule (ScheduleAction::BlockAll slot active).
    Schedule,
    /// Blocked because a public domain resolved to a private/RFC1918 IP address.
    DnsRebinding,
}

impl BlockSource {
    pub fn to_str(&self) -> &'static str {
        match self {
            BlockSource::Blocklist => "blocklist",
            BlockSource::ManagedDomain => "managed_domain",
            BlockSource::RegexFilter => "regex_filter",
            BlockSource::CnameCloaking => "cname_cloaking",
            BlockSource::Schedule => "schedule",
            BlockSource::DnsRebinding => "dns_rebinding",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(BlockSource::Blocklist),
            1 => Some(BlockSource::ManagedDomain),
            2 => Some(BlockSource::RegexFilter),
            3 => Some(BlockSource::CnameCloaking),
            4 => Some(BlockSource::Schedule),
            5 => Some(BlockSource::DnsRebinding),
            _ => None,
        }
    }

    pub fn as_u8(&self) -> u8 {
        match self {
            BlockSource::Blocklist => 0,
            BlockSource::ManagedDomain => 1,
            BlockSource::RegexFilter => 2,
            BlockSource::CnameCloaking => 3,
            BlockSource::Schedule => 4,
            BlockSource::DnsRebinding => 5,
        }
    }
}

impl std::fmt::Display for BlockSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}
