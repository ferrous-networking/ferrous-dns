use serde::{Deserialize, Serialize};

/// Configuration for DGA (Domain Generation Algorithm) detection.
///
/// Two-phase detection: phase 1 runs O(1) checks on the hot path (SLD entropy,
/// consonant ratio, digit ratio, SLD length); phase 2 runs statistical analysis
/// in a background task (n-gram scoring, per-client DGA rate tracking).
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct DgaDetectionConfig {
    /// Master switch — enabled by default. Set to `false` to disable with zero overhead.
    pub enabled: bool,

    /// Action to take when a DGA domain is detected.
    pub action: DgaDetectionAction,

    /// Minimum weighted score (0.0–1.0) across hot-path signals to trigger detection.
    /// Requires multiple signals to fire simultaneously, reducing false positives
    /// on legitimate domains that only appear suspicious in a single dimension.
    pub hot_path_confidence_threshold: f32,

    /// Shannon entropy threshold (bits/char) for the second-level domain.
    pub sld_entropy_threshold: f32,

    /// Maximum SLD length before triggering detection.
    pub sld_max_length: usize,

    /// Consonant ratio threshold (consonants / (consonants + vowels)).
    pub consonant_ratio_threshold: f32,

    /// Digit ratio threshold (digits / total chars).
    pub digit_ratio_threshold: f32,

    /// Bigram deviation score threshold for n-gram analysis.
    pub ngram_score_threshold: f32,

    /// Maximum flagged DGA domains per client per minute before triggering.
    pub dga_rate_per_client: u32,

    /// Minimum confidence score (0.0–1.0) to flag a domain as DGA.
    pub confidence_threshold: f32,

    /// Seconds before idle tracking entries are evicted from memory.
    pub stale_entry_ttl_secs: u64,

    /// Domains exempt from DGA detection.
    pub domain_whitelist: Vec<String>,

    /// Client CIDRs exempt from DGA detection.
    pub client_whitelist: Vec<String>,
}

/// Action to take when a DGA domain is detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DgaDetectionAction {
    /// Log an alert but allow the query to proceed.
    Alert,
    /// Block the query, answering with the configured `[blocking] block_mode`.
    Block,
}

impl DgaDetectionAction {
    /// Config and API spelling (matches the serde rename).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Alert => "alert",
            Self::Block => "block",
        }
    }
}

impl std::str::FromStr for DgaDetectionAction {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "alert" => Ok(Self::Alert),
            "block" => Ok(Self::Block),
            _ => Err(format!(
                "Invalid dns.dga_detection.action '{s}': expected alert or block"
            )),
        }
    }
}

impl Default for DgaDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            action: DgaDetectionAction::Block,
            hot_path_confidence_threshold: 0.40,
            sld_entropy_threshold: 3.5,
            sld_max_length: 24,
            consonant_ratio_threshold: 0.75,
            digit_ratio_threshold: 0.3,
            ngram_score_threshold: 0.6,
            dga_rate_per_client: 10,
            confidence_threshold: 0.65,
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
}
