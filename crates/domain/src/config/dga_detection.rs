use serde::{Deserialize, Serialize};

/// Configuration for DGA (Domain Generation Algorithm) detection.
///
/// Two-phase detection: phase 1 runs O(1) checks on the hot path (SLD entropy,
/// consonant ratio, digit ratio, SLD length); phase 2 runs statistical analysis
/// in a background task (n-gram scoring, per-client DGA rate tracking).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DgaDetectionConfig {
    /// Master switch — enabled by default. Set to `false` to disable with zero overhead.
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Action to take when a DGA domain is detected.
    #[serde(default = "default_action")]
    pub action: DgaDetectionAction,

    // --- Phase 1 (hot path, O(1)) ---
    /// Minimum weighted score (0.0–1.0) across hot-path signals to trigger detection.
    /// Requires multiple signals to fire simultaneously, reducing false positives
    /// on legitimate domains that only appear suspicious in a single dimension.
    #[serde(default = "default_hot_path_confidence_threshold")]
    pub hot_path_confidence_threshold: f32,

    /// Shannon entropy threshold (bits/char) for the second-level domain.
    #[serde(default = "default_sld_entropy_threshold")]
    pub sld_entropy_threshold: f32,

    /// Maximum SLD length before triggering detection.
    #[serde(default = "default_sld_max_length")]
    pub sld_max_length: usize,

    /// Consonant ratio threshold (consonants / (consonants + vowels)).
    #[serde(default = "default_consonant_ratio_threshold")]
    pub consonant_ratio_threshold: f32,

    /// Digit ratio threshold (digits / total chars).
    #[serde(default = "default_digit_ratio_threshold")]
    pub digit_ratio_threshold: f32,

    // --- Phase 2 (background) ---
    /// Bigram deviation score threshold for n-gram analysis.
    #[serde(default = "default_ngram_score_threshold")]
    pub ngram_score_threshold: f32,

    /// Maximum flagged DGA domains per client per minute before triggering.
    #[serde(default = "default_dga_rate_per_client")]
    pub dga_rate_per_client: u32,

    /// Minimum confidence score (0.0–1.0) to flag a domain as DGA.
    #[serde(default = "default_confidence_threshold")]
    pub confidence_threshold: f32,

    /// Seconds before idle tracking entries are evicted from memory.
    #[serde(default = "default_stale_entry_ttl_secs")]
    pub stale_entry_ttl_secs: u64,

    /// Domains exempt from DGA detection.
    #[serde(default)]
    pub domain_whitelist: Vec<String>,

    /// Client CIDRs exempt from DGA detection.
    #[serde(default)]
    pub client_whitelist: Vec<String>,
}

/// Action to take when a DGA domain is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DgaDetectionAction {
    /// Log an alert but allow the query to proceed.
    Alert,
    /// Block the query and return REFUSED.
    Block,
}

impl Default for DgaDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            action: default_action(),
            hot_path_confidence_threshold: default_hot_path_confidence_threshold(),
            sld_entropy_threshold: default_sld_entropy_threshold(),
            sld_max_length: default_sld_max_length(),
            consonant_ratio_threshold: default_consonant_ratio_threshold(),
            digit_ratio_threshold: default_digit_ratio_threshold(),
            ngram_score_threshold: default_ngram_score_threshold(),
            dga_rate_per_client: default_dga_rate_per_client(),
            confidence_threshold: default_confidence_threshold(),
            stale_entry_ttl_secs: default_stale_entry_ttl_secs(),
            domain_whitelist: vec![],
            client_whitelist: vec![],
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_action() -> DgaDetectionAction {
    DgaDetectionAction::Block
}

fn default_hot_path_confidence_threshold() -> f32 {
    0.40
}

fn default_sld_entropy_threshold() -> f32 {
    3.5
}

fn default_sld_max_length() -> usize {
    24
}

fn default_consonant_ratio_threshold() -> f32 {
    0.75
}

fn default_digit_ratio_threshold() -> f32 {
    0.3
}

fn default_ngram_score_threshold() -> f32 {
    0.6
}

fn default_dga_rate_per_client() -> u32 {
    10
}

fn default_confidence_threshold() -> f32 {
    0.65
}

fn default_stale_entry_ttl_secs() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values_are_sane() {
        let config = DgaDetectionConfig::default();
        assert!(config.enabled);
        assert_eq!(config.action, DgaDetectionAction::Block);
        assert!((config.hot_path_confidence_threshold - 0.40).abs() < f32::EPSILON);
        assert!((config.sld_entropy_threshold - 3.5).abs() < f32::EPSILON);
        assert_eq!(config.sld_max_length, 24);
        assert!((config.consonant_ratio_threshold - 0.75).abs() < f32::EPSILON);
        assert!((config.digit_ratio_threshold - 0.3).abs() < f32::EPSILON);
        assert!((config.ngram_score_threshold - 0.6).abs() < f32::EPSILON);
        assert_eq!(config.dga_rate_per_client, 10);
        assert!((config.confidence_threshold - 0.65).abs() < f32::EPSILON);
        assert_eq!(config.stale_entry_ttl_secs, 300);
        assert!(config.domain_whitelist.is_empty());
        assert!(config.client_whitelist.is_empty());
    }

    #[test]
    fn deserializes_empty_toml_with_defaults() {
        let config: DgaDetectionConfig = toml::from_str("").unwrap();
        assert!(config.enabled);
        assert_eq!(config.sld_max_length, 24);
    }

    #[test]
    fn deserializes_partial_toml_preserves_defaults() {
        let toml = r#"
            enabled = true
            action = "alert"
            sld_max_length = 32
        "#;
        let config: DgaDetectionConfig = toml::from_str(toml).unwrap();
        assert!(config.enabled);
        assert_eq!(config.action, DgaDetectionAction::Alert);
        assert_eq!(config.sld_max_length, 32);
        assert!((config.sld_entropy_threshold - 3.5).abs() < f32::EPSILON);
    }

    #[test]
    fn serializes_and_deserializes_roundtrip() {
        let original = DgaDetectionConfig {
            enabled: true,
            action: DgaDetectionAction::Alert,
            hot_path_confidence_threshold: 0.40,
            sld_entropy_threshold: 4.0,
            sld_max_length: 30,
            consonant_ratio_threshold: 0.80,
            digit_ratio_threshold: 0.4,
            ngram_score_threshold: 0.7,
            dga_rate_per_client: 20,
            confidence_threshold: 0.75,
            stale_entry_ttl_secs: 600,
            domain_whitelist: vec!["example.com".to_string()],
            client_whitelist: vec!["10.0.0.0/8".to_string()],
        };
        let toml_str = toml::to_string(&original).unwrap();
        let restored: DgaDetectionConfig = toml::from_str(&toml_str).unwrap();
        assert_eq!(restored.enabled, original.enabled);
        assert_eq!(restored.action, original.action);
        assert_eq!(restored.sld_max_length, original.sld_max_length);
        assert_eq!(restored.domain_whitelist, original.domain_whitelist);
        assert_eq!(restored.client_whitelist, original.client_whitelist);
    }
}
