use serde::{Deserialize, Serialize};

/// Configuration for response IP filtering (C2 IP blocking).
///
/// Downloads IP threat feeds from configurable URLs (e.g. abuse.ch, Feodo Tracker)
/// and checks DNS response IPs against the feed. Blocks or alerts when a resolved
/// IP matches a known C2 server.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseIpFilterConfig {
    /// Master switch — disabled by default (requires user to configure feed URLs).
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Action to take when a C2 IP is detected in a DNS response.
    #[serde(default = "default_action")]
    pub action: ResponseIpFilterAction,

    /// URLs of IP threat feeds (one IP per line, `#` comments).
    #[serde(default)]
    pub ip_list_urls: Vec<String>,

    /// Seconds between feed re-downloads.
    #[serde(default = "default_refresh_interval_secs")]
    pub refresh_interval_secs: u64,

    /// Seconds before an IP not re-confirmed by a feed is evicted.
    #[serde(default = "default_ip_ttl_secs")]
    pub ip_ttl_secs: u64,
}

/// Action to take when a known C2 IP is found in a DNS response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseIpFilterAction {
    /// Log an alert but allow the response to proceed.
    Alert,
    /// Block the response and return REFUSED.
    Block,
}

impl Default for ResponseIpFilterConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            action: default_action(),
            ip_list_urls: vec![],
            refresh_interval_secs: default_refresh_interval_secs(),
            ip_ttl_secs: default_ip_ttl_secs(),
        }
    }
}

fn default_enabled() -> bool {
    false
}

fn default_action() -> ResponseIpFilterAction {
    ResponseIpFilterAction::Block
}

fn default_refresh_interval_secs() -> u64 {
    86400
}

fn default_ip_ttl_secs() -> u64 {
    604800
}
