use serde::{Deserialize, Serialize};

/// Configuration for DNS tunneling detection.
///
/// Two-phase detection: phase 1 runs O(1) checks on the hot path (FQDN length,
/// label length, NULL record type); phase 2 runs statistical analysis in a
/// background task (entropy, query rate, unique subdomains, TXT proportion,
/// NXDOMAIN ratio).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct TunnelingDetectionConfig {
    /// Master switch — enabled by default. Set to `false` to disable with zero overhead.
    pub enabled: bool,

    /// Action to take when tunneling is detected.
    pub action: TunnelingAction,

    /// Maximum allowed FQDN length in bytes before triggering detection.
    pub max_fqdn_length: usize,

    /// Maximum allowed single label length in bytes before triggering detection.
    pub max_label_length: usize,

    /// Block queries for NULL (type 10) record type, commonly abused by tunneling tools.
    pub block_null_queries: bool,

    /// Shannon entropy threshold (bits/char) for subdomain labels.
    pub entropy_threshold: f32,

    /// Maximum queries per minute per client subnet + apex domain pair.
    pub query_rate_per_apex: u32,

    /// Maximum unique subdomains per minute per client subnet + apex domain pair.
    pub unique_subdomain_threshold: u32,

    /// Maximum proportion of TXT queries relative to total queries for a client.
    pub txt_proportion_threshold: f32,

    /// Maximum NXDOMAIN ratio for a client + apex domain pair.
    pub nxdomain_ratio_threshold: f32,

    /// Minimum confidence score (0.0–1.0) to flag a domain as tunneling.
    pub confidence_threshold: f32,

    /// Seconds before idle tracking entries are evicted from memory.
    pub stale_entry_ttl_secs: u64,

    /// Domains exempt from tunneling detection (e.g. CDN domains with long labels).
    pub domain_whitelist: Vec<String>,

    /// Client CIDRs exempt from tunneling detection.
    pub client_whitelist: Vec<String>,
}

/// Action to take when DNS tunneling is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelingAction {
    /// Log an alert but allow the query to proceed.
    Alert,
    /// Block the query, answering with the configured `[blocking] block_mode`.
    Block,
    /// Throttle the response (future use).
    Throttle,
}

impl TunnelingAction {
    /// Config and API spelling (matches the serde rename).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Block => "block",
            Self::Throttle => "throttle",
        }
    }
}

impl std::str::FromStr for TunnelingAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "alert" => Ok(Self::Alert),
            "block" => Ok(Self::Block),
            "throttle" => Ok(Self::Throttle),
            _ => Err(format!(
                "Invalid dns.tunneling_detection.action '{s}': expected alert, block or throttle"
            )),
        }
    }
}

impl Default for TunnelingDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: TunnelingAction::Block,
            max_fqdn_length: 120,
            max_label_length: 50,
            block_null_queries: true,
            entropy_threshold: 3.8,
            query_rate_per_apex: 50,
            unique_subdomain_threshold: 30,
            txt_proportion_threshold: 0.05,
            nxdomain_ratio_threshold: 0.20,
            confidence_threshold: 0.7,
            stale_entry_ttl_secs: 300,
            domain_whitelist: vec![],
            client_whitelist: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserializes_empty_toml_with_defaults() {
        let config: TunnelingDetectionConfig = toml::from_str("").unwrap();
        assert!(config.enabled);
        assert_eq!(config.max_fqdn_length, 120);
    }

    #[test]
    fn deserializes_partial_toml_preserves_defaults() {
        let toml = r#"
            enabled = true
            action = "alert"
            max_fqdn_length = 200
        "#;
        let config: TunnelingDetectionConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.action, TunnelingAction::Alert);
        assert_eq!(config.max_fqdn_length, 200);
        assert_eq!(config.max_label_length, 50);
    }
}
