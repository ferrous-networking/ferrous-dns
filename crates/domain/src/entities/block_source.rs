use serde::{Deserialize, Serialize};

/// Source that caused a DNS query to be blocked.
///
/// Numeric values from [`as_u8`]/[`from_u8`] are persisted in the database.
/// **Never reorder or reuse values** — doing so would corrupt historical records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockSource {
    /// Matched a domain in a downloaded blocklist.
    Blocklist,
    /// Matched a manually managed (custom) blocked domain.
    ManagedDomain,
    /// Matched a user-defined regex filter.
    RegexFilter,
    /// Blocked because a CNAME chain pointed to a blocked domain.
    CnameCloaking,
    /// Blocked by a time-based schedule rule (ScheduleAction::BlockAll slot active).
    Schedule,
    /// Blocked because a public domain resolved to a private/RFC1918 IP address.
    DnsRebinding,
    /// Blocked by DNS query rate limiting.
    RateLimit,
    /// Blocked by DNS tunneling detection.
    DnsTunneling,
    /// Blocked by NXDomain hijack detection (ISP intercepting NXDOMAIN responses).
    NxdomainHijack,
    /// Blocked by response IP filtering (known C2 IP in DNS response).
    ResponseIpFilter,
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
            BlockSource::RateLimit => "rate_limit",
            BlockSource::DnsTunneling => "dns_tunneling",
            BlockSource::NxdomainHijack => "nxdomain_hijack",
            BlockSource::ResponseIpFilter => "response_ip_filter",
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
            6 => Some(BlockSource::RateLimit),
            7 => Some(BlockSource::DnsTunneling),
            8 => Some(BlockSource::NxdomainHijack),
            9 => Some(BlockSource::ResponseIpFilter),
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
            BlockSource::RateLimit => 6,
            BlockSource::DnsTunneling => 7,
            BlockSource::NxdomainHijack => 8,
            BlockSource::ResponseIpFilter => 9,
        }
    }
}

impl std::fmt::Display for BlockSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}
