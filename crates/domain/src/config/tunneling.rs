use serde::{Deserialize, Serialize};

/// Configuration for DNS tunneling detection.
///
/// Two-phase detection: phase 1 runs O(1) checks on the hot path (FQDN length,
/// label length, NULL record type); phase 2 runs statistical analysis in a
/// background task (entropy, query rate, unique subdomains, TXT proportion,
/// NXDOMAIN ratio).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TunnelingDetectionConfig {
    /// Master switch — enabled by default. Set to `false` to disable with zero overhead.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Action to take when tunneling is detected.
    #[serde(default = "default_action")]
    pub action: TunnelingAction,

    // --- Phase 1 (hot path, O(1)) ---
    /// Maximum allowed FQDN length in bytes before triggering detection.
    #[serde(default = "default_max_fqdn_length")]
    pub max_fqdn_length: usize,

    /// Maximum allowed single label length in bytes before triggering detection.
    #[serde(default = "default_max_label_length")]
    pub max_label_length: usize,

    /// Block queries for NULL (type 10) record type, commonly abused by tunneling tools.
    #[serde(default = "default_block_null_queries")]
    pub block_null_queries: bool,

    // --- Phase 2 (background) ---
    /// Shannon entropy threshold (bits/char) for subdomain labels.
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f32,

    /// Maximum queries per minute per client subnet + apex domain pair.
    #[serde(default = "default_query_rate_per_apex")]
    pub query_rate_per_apex: u32,

    /// Maximum unique subdomains per minute per client subnet + apex domain pair.
    #[serde(default = "default_unique_subdomain_threshold")]
    pub unique_subdomain_threshold: u32,

    /// Maximum proportion of TXT queries relative to total queries for a client.
    #[serde(default = "default_txt_proportion_threshold")]
    pub txt_proportion_threshold: f32,

    /// Maximum NXDOMAIN ratio for a client + apex domain pair.
    #[serde(default = "default_nxdomain_ratio_threshold")]
    pub nxdomain_ratio_threshold: f32,

    /// Minimum confidence score (0.0–1.0) to flag a domain as tunneling.
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f32,

    /// Seconds before idle tracking entries are evicted from memory.
    #[serde(default = "default_stale_ttl")]
    pub stale_entry_ttl_secs: u64,

    /// Domains exempt from tunneling detection (e.g. CDN domains with long labels).
    #[serde(default)]
    pub domain_whitelist: Vec<String>,

    /// Client CIDRs exempt from tunneling detection.
    #[serde(default)]
    pub client_whitelist: Vec<String>,
}

/// Action to take when DNS tunneling is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelingAction {
    /// Log an alert but allow the query to proceed.
    Alert,
    /// Block the query and return REFUSED.
    Block,
    /// Throttle the response (future use).
    Throttle,
}

impl Default for TunnelingDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            action: default_action(),
            max_fqdn_length: default_max_fqdn_length(),
            max_label_length: default_max_label_length(),
            block_null_queries: default_block_null_queries(),
            entropy_threshold: default_entropy_threshold(),
            query_rate_per_apex: default_query_rate_per_apex(),
            unique_subdomain_threshold: default_unique_subdomain_threshold(),
            txt_proportion_threshold: default_txt_proportion_threshold(),
            nxdomain_ratio_threshold: default_nxdomain_ratio_threshold(),
            confidence_threshold: default_confidence_threshold(),
            stale_entry_ttl_secs: default_stale_ttl(),
            domain_whitelist: vec![],
            client_whitelist: vec![],
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_action() -> TunnelingAction {
    TunnelingAction::Block
}

fn default_max_fqdn_length() -> usize {
    120
}

fn default_max_label_length() -> usize {
    50
}

fn default_block_null_queries() -> bool {
    true
}

fn default_entropy_threshold() -> f32 {
    3.8
}

fn default_query_rate_per_apex() -> u32 {
    50
}

fn default_unique_subdomain_threshold() -> u32 {
    30
}

fn default_txt_proportion_threshold() -> f32 {
    0.05
}

fn default_nxdomain_ratio_threshold() -> f32 {
    0.20
}

fn default_confidence_threshold() -> f32 {
    0.7
}

fn default_stale_ttl() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_are_sane() {
        let config = TunnelingDetectionConfig::default();
        assert!(config.enabled);
        assert_eq!(config.action, TunnelingAction::Block);
        assert_eq!(config.max_fqdn_length, 120);
        assert_eq!(config.max_label_length, 50);
        assert!(config.block_null_queries);
        assert!((config.entropy_threshold - 3.8).abs() < f32::EPSILON);
        assert_eq!(config.query_rate_per_apex, 50);
        assert_eq!(config.unique_subdomain_threshold, 30);
        assert!((config.confidence_threshold - 0.7).abs() < f32::EPSILON);
        assert_eq!(config.stale_entry_ttl_secs, 300);
        assert!(config.domain_whitelist.is_empty());
        assert!(config.client_whitelist.is_empty());
    }

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

    #[test]
    fn serializes_and_deserializes_roundtrip() {
        let original = TunnelingDetectionConfig {
            enabled: true,
            action: TunnelingAction::Alert,
            max_fqdn_length: 150,
            max_label_length: 60,
            block_null_queries: false,
            entropy_threshold: 4.0,
            query_rate_per_apex: 100,
            unique_subdomain_threshold: 50,
            txt_proportion_threshold: 0.10,
            nxdomain_ratio_threshold: 0.30,
            confidence_threshold: 0.8,
            stale_entry_ttl_secs: 600,
            domain_whitelist: vec!["cdn.example.com".to_string()],
            client_whitelist: vec!["10.0.0.0/8".to_string()],
        };
        let toml_str = toml::to_string(&original).unwrap();
        let restored: TunnelingDetectionConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.enabled, original.enabled);
        assert_eq!(restored.action, original.action);
        assert_eq!(restored.max_fqdn_length, original.max_fqdn_length);
        assert_eq!(restored.max_label_length, original.max_label_length);
        assert_eq!(restored.block_null_queries, original.block_null_queries);
        assert_eq!(restored.domain_whitelist, original.domain_whitelist);
        assert_eq!(restored.client_whitelist, original.client_whitelist);
    }
}
