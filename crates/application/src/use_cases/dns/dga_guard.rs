use super::domain_heuristics::{char_ratios, extract_apex, shannon_entropy};
use ferrous_dns_domain::{DgaDetectionAction, DgaDetectionConfig};
use std::net::IpAddr;
use std::sync::Arc;

/// Outcome of the hot-path DGA check (phase 1).
pub(super) enum DgaVerdict {
    /// No DGA signal detected.
    Clean,
    /// A DGA signal was detected with measurable details.
    Detected {
        signal: &'static str,
        measured: f32,
        threshold: f32,
    },
}

/// Signal weights for phase-1 hot-path mini-scoring.
const HP_WEIGHT_SLD_ENTROPY: f32 = 0.30;
const HP_WEIGHT_CONSONANT_RATIO: f32 = 0.25;
const HP_WEIGHT_DIGIT_RATIO: f32 = 0.20;
const HP_WEIGHT_SLD_LENGTH: f32 = 0.25;

/// Guards DNS queries against DGA domains on the hot path.
///
/// Performs O(1) checks: SLD entropy, consonant ratio, digit ratio, SLD length.
/// Uses weighted mini-scoring: only triggers when multiple signals exceed their
/// thresholds simultaneously, reducing false positives on legitimate domains.
/// N-gram analysis runs in a separate background task.
pub(super) struct DgaGuard {
    enabled: bool,
    action: DgaDetectionAction,
    hot_path_confidence_threshold: f32,
    sld_entropy_threshold: f32,
    sld_max_length: usize,
    consonant_ratio_threshold: f32,
    digit_ratio_threshold: f32,
}

impl DgaGuard {
    pub(super) fn from_config(config: &DgaDetectionConfig) -> Self {
        Self {
            enabled: config.enabled,
            action: config.action,
            hot_path_confidence_threshold: config.hot_path_confidence_threshold,
            sld_entropy_threshold: config.sld_entropy_threshold,
            sld_max_length: config.sld_max_length,
            consonant_ratio_threshold: config.consonant_ratio_threshold,
            digit_ratio_threshold: config.digit_ratio_threshold,
        }
    }

    pub(super) fn disabled() -> Self {
        let mut guard = Self::from_config(&DgaDetectionConfig::default());
        guard.enabled = false;
        guard
    }

    pub(super) fn action(&self) -> DgaDetectionAction {
        self.action
    }

    /// Performs O(1) DGA checks on the hot path using weighted mini-scoring.
    ///
    /// Accumulates weights from all triggered signals and only returns `Detected`
    /// when the combined score exceeds `hot_path_confidence_threshold`. This prevents
    /// false positives on legitimate domains that appear suspicious in only one dimension
    /// (e.g., CDN domains with high entropy but normal consonant ratio).
    ///
    /// Zero heap allocations: `domain` is `&str`, SLD is a slice.
    pub(super) fn check(&self, domain: &str) -> DgaVerdict {
        if !self.enabled {
            return DgaVerdict::Clean;
        }

        let sld = match extract_sld(domain) {
            Some(s) if s.len() > 3 => s,
            _ => return DgaVerdict::Clean,
        };

        let long = sld.len() > self.sld_max_length;
        let (consonants, vowels, digits, total) = char_ratios(sld);
        let alpha = consonants + vowels;
        let consonant_ratio = (alpha > 0).then(|| consonants as f32 / alpha as f32);
        let consonant_heavy = consonant_ratio.is_some_and(|r| r > self.consonant_ratio_threshold);
        let digit_ratio = (total > 0).then(|| digits as f32 / total as f32);
        let digit_heavy = digit_ratio.is_some_and(|r| r > self.digit_ratio_threshold);

        // Each sum adds the weights in the same order, so its rounding matches
        // the score's. The entropy is the costly signal, and most names fire
        // none of the others, so it is skipped when even its full weight could
        // not reach the threshold.
        let weight = |fired: bool, value: f32| if fired { value } else { 0.0 };
        let ceiling = weight(long, HP_WEIGHT_SLD_LENGTH)
            + HP_WEIGHT_SLD_ENTROPY
            + weight(consonant_heavy, HP_WEIGHT_CONSONANT_RATIO)
            + weight(digit_heavy, HP_WEIGHT_DIGIT_RATIO);
        if ceiling < self.hot_path_confidence_threshold {
            return DgaVerdict::Clean;
        }

        let entropy = shannon_entropy(sld.as_bytes());
        let high_entropy = entropy > self.sld_entropy_threshold;
        let confidence = weight(long, HP_WEIGHT_SLD_LENGTH)
            + weight(high_entropy, HP_WEIGHT_SLD_ENTROPY)
            + weight(consonant_heavy, HP_WEIGHT_CONSONANT_RATIO)
            + weight(digit_heavy, HP_WEIGHT_DIGIT_RATIO);
        if confidence < self.hot_path_confidence_threshold {
            return DgaVerdict::Clean;
        }

        let mut top = TopSignal::default();
        if long {
            top.offer("sld_length", sld.len() as f32, self.sld_max_length as f32);
        }
        if high_entropy {
            top.offer("sld_entropy", entropy, self.sld_entropy_threshold);
        }
        if let Some(ratio) = consonant_ratio.filter(|_| consonant_heavy) {
            top.offer("consonant_ratio", ratio, self.consonant_ratio_threshold);
        }
        if let Some(ratio) = digit_ratio.filter(|_| digit_heavy) {
            top.offer("digit_ratio", ratio, self.digit_ratio_threshold);
        }
        DgaVerdict::Detected {
            signal: top.name,
            measured: top.measured,
            threshold: top.threshold,
        }
    }
}

/// Triggered signal with the highest relative excess over its threshold, so logs
/// name the most diagnostic signal rather than the heaviest weight.
struct TopSignal {
    name: &'static str,
    measured: f32,
    threshold: f32,
    excess: f32,
}

impl Default for TopSignal {
    fn default() -> Self {
        Self {
            name: "none",
            measured: 0.0,
            threshold: 0.0,
            excess: 0.0,
        }
    }
}

impl TopSignal {
    #[inline]
    fn offer(&mut self, name: &'static str, measured: f32, threshold: f32) {
        let excess = measured / threshold;
        if excess > self.excess {
            *self = Self {
                name,
                measured,
                threshold,
                excess,
            };
        }
    }
}

/// Event emitted to the background DGA analysis task after each query.
pub struct DgaAnalysisEvent {
    pub domain: Arc<str>,
    pub client_ip: IpAddr,
}

/// Extracts the second-level domain (SLD) from a domain name.
///
/// E.g., `xjk4f9a2h.com` → `xjk4f9a2h`, `sub.example.co.uk` → `example`.
fn extract_sld(domain: &str) -> Option<&str> {
    let apex = extract_apex(domain);
    // SLD is the first label of the apex
    apex.split('.').next().filter(|s| !s.is_empty())
}
