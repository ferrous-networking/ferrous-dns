use serde::{Deserialize, Serialize};

/// Configuration for NXDomain hijack detection.
///
/// ISPs intercept NXDOMAIN responses and return advertising server IPs instead,
/// violating RFC 1035. A background probe job tests each upstream with random
/// `.invalid` domains; if an upstream returns A/AAAA records instead of NXDOMAIN,
/// the hijack IPs are recorded. On the hot path, responses containing known
/// hijack IPs are converted back to NXDOMAIN.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NxdomainHijackConfig {
    /// Master switch — enabled by default.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Action to take when a hijacked response is detected.
    #[serde(default = "default_action")]
    pub action: NxdomainHijackAction,

    /// Seconds between probe rounds for each upstream.
    #[serde(default = "default_probe_interval_secs")]
    pub probe_interval_secs: u64,

    /// Milliseconds to wait for a probe response before timing out.
    #[serde(default = "default_probe_timeout_ms")]
    pub probe_timeout_ms: u64,

    /// Number of probe queries per upstream per round.
    #[serde(default = "default_probes_per_round")]
    pub probes_per_round: u8,

    /// Seconds before an unconfirmed hijack IP is evicted.
    #[serde(default = "default_hijack_ip_ttl_secs")]
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

impl Default for NxdomainHijackConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            action: default_action(),
            probe_interval_secs: default_probe_interval_secs(),
            probe_timeout_ms: default_probe_timeout_ms(),
            probes_per_round: default_probes_per_round(),
            hijack_ip_ttl_secs: default_hijack_ip_ttl_secs(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_action() -> NxdomainHijackAction {
    NxdomainHijackAction::Block
}

fn default_probe_interval_secs() -> u64 {
    300
}

fn default_probe_timeout_ms() -> u64 {
    5000
}

fn default_probes_per_round() -> u8 {
    3
}

fn default_hijack_ip_ttl_secs() -> u64 {
    3600
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_are_sane() {
        let config = NxdomainHijackConfig::default();
        assert!(config.enabled);
        assert_eq!(config.action, NxdomainHijackAction::Block);
        assert_eq!(config.probe_interval_secs, 300);
        assert_eq!(config.probe_timeout_ms, 5000);
        assert_eq!(config.probes_per_round, 3);
        assert_eq!(config.hijack_ip_ttl_secs, 3600);
    }

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

    #[test]
    fn deserializes_block_action() {
        let toml = r#"action = "block""#;
        let config: NxdomainHijackConfig = toml::from_str(toml).unwrap();
        assert_eq!(config.action, NxdomainHijackAction::Block);
    }

    #[test]
    fn serializes_and_deserializes_roundtrip() {
        let original = NxdomainHijackConfig {
            enabled: true,
            action: NxdomainHijackAction::Alert,
            probe_interval_secs: 600,
            probe_timeout_ms: 3000,
            probes_per_round: 5,
            hijack_ip_ttl_secs: 7200,
        };
        let toml_str = toml::to_string(&original).unwrap();
        let restored: NxdomainHijackConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.enabled, original.enabled);
        assert_eq!(restored.action, original.action);
        assert_eq!(restored.probe_interval_secs, original.probe_interval_secs);
        assert_eq!(restored.probe_timeout_ms, original.probe_timeout_ms);
        assert_eq!(restored.probes_per_round, original.probes_per_round);
        assert_eq!(restored.hijack_ip_ttl_secs, original.hijack_ip_ttl_secs);
    }
}
