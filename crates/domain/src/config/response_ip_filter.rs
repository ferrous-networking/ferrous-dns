use serde::{Deserialize, Serialize};

/// Configuration for response IP filtering (C2 IP blocking).
///
/// Downloads IP threat feeds from configurable URLs (e.g. abuse.ch, Feodo Tracker)
/// and checks DNS response IPs against the feed. Blocks or alerts when a resolved
/// IP matches a known C2 server.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ResponseIpFilterConfig {
    /// Master switch — disabled by default (requires user to configure feed URLs).
    pub enabled: bool,

    /// Action to take when a C2 IP is detected in a DNS response.
    pub action: ResponseIpFilterAction,

    /// URLs of IP threat feeds (one IP per line, `#` comments).
    pub ip_list_urls: Vec<String>,

    /// Seconds between feed re-downloads.
    pub refresh_interval_secs: u64,

    /// Seconds before an IP not re-confirmed by a feed is evicted.
    pub ip_ttl_secs: u64,
}

/// Action to take when a known C2 IP is found in a DNS response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseIpFilterAction {
    /// Log an alert but allow the response to proceed.
    Alert,
    /// Block the response, answering with the configured `[blocking] block_mode`.
    Block,
}

impl ResponseIpFilterAction {
    /// Config and API spelling (matches the serde rename).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Block => "block",
        }
    }
}

impl std::str::FromStr for ResponseIpFilterAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "alert" => Ok(Self::Alert),
            "block" => Ok(Self::Block),
            _ => Err(format!(
                "Invalid dns.response_ip_filter.action '{s}': expected alert or block"
            )),
        }
    }
}

impl Default for ResponseIpFilterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action: ResponseIpFilterAction::Block,
            ip_list_urls: vec![],
            refresh_interval_secs: 86400,
            ip_ttl_secs: 604800,
        }
    }
}
