use serde::{Deserialize, Serialize};

/// Configuration for NXDomain hijack detection.
///
/// ISPs intercept NXDOMAIN responses and return advertising server IPs instead,
/// violating RFC 1035. A background probe job tests each upstream with random
/// `.invalid` domains; if an upstream returns A/AAAA records instead of NXDOMAIN,
/// the hijack IPs are recorded. On the hot path, responses containing known
/// hijack IPs are converted back to NXDOMAIN.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct NxdomainHijackConfig {
    /// Master switch — enabled by default.
    pub enabled: bool,

    /// Action to take when a hijacked response is detected.
    pub action: NxdomainHijackAction,

    /// Seconds between probe rounds for each upstream.
    pub probe_interval_secs: u64,

    /// Milliseconds to wait for a probe response before timing out.
    pub probe_timeout_ms: u64,

    /// Number of probe queries per upstream per round.
    pub probes_per_round: u8,

    /// Seconds before an unconfirmed hijack IP is evicted.
    pub hijack_ip_ttl_secs: u64,
}

/// Action to take when an NXDomain hijack is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NxdomainHijackAction {
    /// Log an alert but allow the response to proceed.
    Alert,
    /// Convert the hijacked response back to NXDOMAIN.
    Block,
}

impl NxdomainHijackAction {
    /// Config and API spelling (matches the serde rename).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Block => "block",
        }
    }
}

impl std::str::FromStr for NxdomainHijackAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "alert" => Ok(Self::Alert),
            "block" => Ok(Self::Block),
            _ => Err(format!(
                "Invalid dns.nxdomain_hijack.action '{s}': expected alert or block"
            )),
        }
    }
}

impl Default for NxdomainHijackConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: NxdomainHijackAction::Block,
            probe_interval_secs: 300,
            probe_timeout_ms: 5000,
            probes_per_round: 3,
            hijack_ip_ttl_secs: 3600,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_empty_toml_with_defaults() {
        let config: NxdomainHijackConfig = toml::from_str("").unwrap();
        assert!(config.enabled);
        assert_eq!(config.probe_interval_secs, 300);
    }

    #[test]
    fn deserializes_partial_toml_preserves_defaults() {
        let toml = r#"
            enabled = true
            action = "alert"
            probe_interval_secs = 600
        "#;
        let config: NxdomainHijackConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.action, NxdomainHijackAction::Alert);
        assert_eq!(config.probe_interval_secs, 600);
        assert_eq!(config.probe_timeout_ms, 5000);
    }
}
