use crate::DomainError;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

/// Source that caused a DNS query to be blocked.
///
/// The [`BlockSource::to_str`] names are persisted in the query log, so never
/// rename them. The `u8` codes only live in the in-memory decision cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum BlockSource {
    /// Matched a domain in a downloaded blocklist.
    Blocklist = 0,
    /// Matched a manually managed (custom) blocked domain.
    ManagedDomain = 1,
    RegexFilter = 2,
    /// Blocked because a CNAME chain pointed to a blocked domain.
    CnameCloaking = 3,
    /// A `ScheduleAction::BlockAll` slot was active.
    Schedule = 4,
    /// A public domain resolved to a private/RFC1918 address.
    DnsRebinding = 5,
    RateLimit = 6,
    DnsTunneling = 7,
    /// An ISP rewrote an NXDOMAIN into an answer.
    NxdomainHijack = 8,
    /// The response carried a known C2 IP.
    ResponseIpFilter = 9,
    /// Domain Generation Algorithm detection.
    DgaDetection = 10,
    /// `block_non_fqdn` refused a single-label name.
    NonFqdn = 11,
    /// `block_private_ptr` refused a reverse lookup for a private range.
    PrivatePtr = 12,
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
            BlockSource::DgaDetection => "dga_detection",
            BlockSource::NonFqdn => "non_fqdn",
            BlockSource::PrivatePtr => "private_ptr",
        }
    }

    /// Threat-detection verdicts, as opposed to policy blocks. Dashboards count
    /// these as "malware detected"; exhaustive so a new source must be classified.
    pub fn is_malware(self) -> bool {
        match self {
            BlockSource::DnsRebinding
            | BlockSource::DnsTunneling
            | BlockSource::NxdomainHijack
            | BlockSource::ResponseIpFilter
            | BlockSource::DgaDetection => true,
            BlockSource::Blocklist
            | BlockSource::ManagedDomain
            | BlockSource::RegexFilter
            | BlockSource::CnameCloaking
            | BlockSource::Schedule
            | BlockSource::RateLimit
            | BlockSource::NonFqdn
            | BlockSource::PrivatePtr => false,
        }
    }

    /// Every variant, indexed by its `u8` code.
    pub const ALL: [BlockSource; 13] = [
        BlockSource::Blocklist,
        BlockSource::ManagedDomain,
        BlockSource::RegexFilter,
        BlockSource::CnameCloaking,
        BlockSource::Schedule,
        BlockSource::DnsRebinding,
        BlockSource::RateLimit,
        BlockSource::DnsTunneling,
        BlockSource::NxdomainHijack,
        BlockSource::ResponseIpFilter,
        BlockSource::DgaDetection,
        BlockSource::NonFqdn,
        BlockSource::PrivatePtr,
    ];

    pub fn from_u8(v: u8) -> Option<Self> {
        Self::ALL.get(usize::from(v)).copied()
    }

    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl FromStr for BlockSource {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|source| source.to_str() == s)
            .ok_or_else(|| DomainError::InvalidInput(format!("unknown block source: '{s}'")))
    }
}

impl std::fmt::Display for BlockSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.to_str())
    }
}
