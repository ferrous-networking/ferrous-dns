use ferrous_dns_domain::{DgaDetectionAction, DgaDetectionConfig};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
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

/// Parsed CIDR range for client whitelist matching.
struct CidrRange {
    network: u128,
    mask: u128,
}

impl CidrRange {
    fn parse(cidr: &str) -> Option<Self> {
        let (addr_str, prefix_str) = cidr.split_once('/')?;
        let prefix: u8 = prefix_str.parse().ok()?;

        if let Ok(v4) = addr_str.parse::<Ipv4Addr>() {
            if prefix > 32 {
                return None;
            }
            let v4_bits = u32::from(v4);
            let v4_mask = if prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - prefix)
            };
            let mapped = (v4_bits as u128) | 0xFFFF_0000_0000u128;
            let mapped_mask = (v4_mask as u128) | 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000u128;
            Some(Self {
                network: mapped & mapped_mask,
                mask: mapped_mask,
            })
        } else if let Ok(v6) = addr_str.parse::<Ipv6Addr>() {
            if prefix > 128 {
                return None;
            }
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0u128
            } else {
                (u128::MAX >> (128 - prefix)) << (128 - prefix)
            };
            Some(Self {
                network: bits & mask,
                mask,
            })
        } else {
            None
        }
    }

    fn contains(&self, ip: IpAddr) -> bool {
        let bits = match ip {
            IpAddr::V4(v4) => u32::from(v4) as u128 | 0xFFFF_0000_0000u128,
            IpAddr::V6(v6) => u128::from(v6),
        };
        (bits & self.mask) == self.network
    }
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
    domain_whitelist: HashSet<Box<str>>,
    client_whitelist: Vec<CidrRange>,
}

impl DgaGuard {
    /// Creates a guard from the domain-layer configuration.
    pub(super) fn from_config(config: &DgaDetectionConfig) -> Self {
        Self {
            enabled: config.enabled,
            action: config.action,
            hot_path_confidence_threshold: config.hot_path_confidence_threshold,
            sld_entropy_threshold: config.sld_entropy_threshold,
            sld_max_length: config.sld_max_length,
            consonant_ratio_threshold: config.consonant_ratio_threshold,
            digit_ratio_threshold: config.digit_ratio_threshold,
            domain_whitelist: config
                .domain_whitelist
                .iter()
                .map(|s| s.to_lowercase().into_boxed_str())
                .collect(),
            client_whitelist: config
                .client_whitelist
                .iter()
                .filter_map(|s| CidrRange::parse(s))
                .collect(),
        }
    }

    /// Creates a disabled guard that never triggers.
    pub(super) fn disabled() -> Self {
        let mut guard = Self::from_config(&DgaDetectionConfig::default());
        guard.enabled = false;
        guard
    }

    /// Returns the configured action for detected DGA domains.
    pub(super) fn action(&self) -> DgaDetectionAction {
        self.action
    }

    /// Returns `true` if the client IP is in the configured whitelist.
    pub(super) fn is_client_whitelisted(&self, client_ip: IpAddr) -> bool {
        self.client_whitelist
            .iter()
            .any(|cidr| cidr.contains(client_ip))
    }

    /// Performs O(1) DGA checks on the hot path using weighted mini-scoring.
    ///
    /// Accumulates weights from all triggered signals and only returns `Detected`
    /// when the combined score exceeds `hot_path_confidence_threshold`. This prevents
    /// false positives on legitimate domains that appear suspicious in only one dimension
    /// (e.g., CDN domains with high entropy but normal consonant ratio).
    ///
    /// Zero heap allocations: `domain` is `&str`, SLD is a slice.
    pub(super) fn check(&self, domain: &str, client_ip: IpAddr) -> DgaVerdict {
        if !self.enabled {
            return DgaVerdict::Clean;
        }

        if self.is_client_whitelisted(client_ip) {
            return DgaVerdict::Clean;
        }

        // O(1) HashSet lookup (case-insensitive via pre-lowercased keys)
        if domain.len() <= 253 {
            let mut buf = [0u8; 253];
            let bytes = domain.as_bytes();
            let len = bytes.len();
            for (i, &b) in bytes.iter().enumerate() {
                buf[i] = b.to_ascii_lowercase();
            }
            // SAFETY: input is ASCII DNS domain name, lowercasing preserves UTF-8
            let lower = unsafe { std::str::from_utf8_unchecked(&buf[..len]) };
            if self.domain_whitelist.contains(lower) {
                return DgaVerdict::Clean;
            }
        }

        let sld = match extract_sld(domain) {
            Some(s) if s.len() > 3 => s,
            _ => return DgaVerdict::Clean,
        };

        let mut confidence: f32 = 0.0;
        let mut top_signal: &'static str = "none";
        let mut top_measured: f32 = 0.0;
        let mut top_threshold: f32 = 0.0;
        let mut top_excess: f32 = 0.0;

        // Tracks the signal with the highest relative excess over its threshold,
        // so logs reflect the most diagnostically useful signal — not just the
        // heaviest weight.
        macro_rules! track_signal {
            ($name:expr, $measured:expr, $threshold:expr) => {
                let excess = $measured / $threshold;
                if excess > top_excess {
                    top_excess = excess;
                    top_signal = $name;
                    top_measured = $measured;
                    top_threshold = $threshold;
                }
            };
        }

        if sld.len() > self.sld_max_length {
            confidence += HP_WEIGHT_SLD_LENGTH;
            track_signal!("sld_length", sld.len() as f32, self.sld_max_length as f32);
        }

        let entropy = shannon_entropy(sld.as_bytes());
        if entropy > self.sld_entropy_threshold {
            confidence += HP_WEIGHT_SLD_ENTROPY;
            track_signal!("sld_entropy", entropy, self.sld_entropy_threshold);
        }

        let (consonants, vowels, digits, total) = char_ratios(sld);
        if total > 0 {
            let alpha = consonants + vowels;
            if alpha > 0 {
                let consonant_ratio = consonants as f32 / alpha as f32;
                if consonant_ratio > self.consonant_ratio_threshold {
                    confidence += HP_WEIGHT_CONSONANT_RATIO;
                    track_signal!(
                        "consonant_ratio",
                        consonant_ratio,
                        self.consonant_ratio_threshold
                    );
                }
            }

            let digit_ratio = digits as f32 / total as f32;
            if digit_ratio > self.digit_ratio_threshold {
                confidence += HP_WEIGHT_DIGIT_RATIO;
                track_signal!("digit_ratio", digit_ratio, self.digit_ratio_threshold);
            }
        }

        let _ = top_excess;

        if confidence >= self.hot_path_confidence_threshold {
            return DgaVerdict::Detected {
                signal: top_signal,
                measured: top_measured,
                threshold: top_threshold,
            };
        }

        DgaVerdict::Clean
    }
}

/// Event emitted to the background DGA analysis task after each query.
pub struct DgaAnalysisEvent {
    pub domain: Arc<str>,
    pub client_ip: IpAddr,
}

/// Computes Shannon entropy in bits per character.
///
/// Uses a stack-allocated histogram `[u32; 256]` (~1 KB) — zero heap allocation.
#[inline]
fn shannon_entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f32;
    let mut entropy: f32 = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f32 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Computes character class counts for DGA detection.
///
/// Returns (consonants, vowels, digits, total_chars).
#[inline]
fn char_ratios(sld: &str) -> (u32, u32, u32, u32) {
    let mut consonants = 0u32;
    let mut vowels = 0u32;
    let mut digits = 0u32;
    let mut total = 0u32;

    for &b in sld.as_bytes() {
        total += 1;
        let lower = b.to_ascii_lowercase();
        match lower {
            b'a' | b'e' | b'i' | b'o' | b'u' => vowels += 1,
            b'b'..=b'd' | b'f'..=b'h' | b'j'..=b'n' | b'p'..=b't' | b'v'..=b'z' => {
                consonants += 1;
            }
            b'0'..=b'9' => digits += 1,
            _ => {} // hyphens and other chars don't count
        }
    }

    (consonants, vowels, digits, total)
}

/// Common two-level TLDs where the apex requires 3 labels.
const COMPOUND_TLDS: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk", "co.jp", "or.jp", "ne.jp", "ac.jp",
    "go.jp", "com.br", "org.br", "net.br", "gov.br", "edu.br", "com.au", "org.au", "net.au",
    "edu.au", "gov.au", "co.nz", "org.nz", "net.nz", "co.za", "org.za", "co.in", "org.in",
    "net.in", "gen.in", "com.cn", "org.cn", "net.cn", "gov.cn", "edu.cn", "com.tw", "org.tw",
    "com.hk", "org.hk", "com.sg", "org.sg", "com.my", "org.my", "co.kr", "or.kr", "co.il",
    "org.il", "com.ar", "org.ar", "com.mx", "org.mx", "com.co", "org.co", "com.ve", "com.pe",
    "com.tr", "org.tr", "co.th", "or.th", "com.ph", "org.ph", "com.ng", "org.ng", "co.ke", "or.ke",
    "com.eg", "org.eg", "com.pk", "org.pk", "com.bd", "org.bd",
];

fn is_compound_tld(domain: &str) -> bool {
    let bytes = domain.as_bytes();
    let mut dot_count = 0;
    for (i, &b) in bytes.iter().enumerate().rev() {
        if b == b'.' {
            dot_count += 1;
            if dot_count == 2 {
                let last_two = &domain[i + 1..];
                return COMPOUND_TLDS
                    .iter()
                    .any(|tld| last_two.eq_ignore_ascii_case(tld));
            }
        }
    }
    if dot_count == 1 {
        return COMPOUND_TLDS
            .iter()
            .any(|tld| domain.eq_ignore_ascii_case(tld));
    }
    false
}

/// Extracts the apex domain from a domain name.
fn extract_apex(domain: &str) -> &str {
    let target_dots = if is_compound_tld(domain) { 3 } else { 2 };
    let bytes = domain.as_bytes();
    let mut dot_count = 0;
    for (i, &b) in bytes.iter().enumerate().rev() {
        if b == b'.' {
            dot_count += 1;
            if dot_count == target_dots {
                return &domain[i + 1..];
            }
        }
    }
    domain
}

/// Extracts the second-level domain (SLD) from a domain name.
///
/// E.g., `xjk4f9a2h.com` → `xjk4f9a2h`, `sub.example.co.uk` → `example`.
fn extract_sld(domain: &str) -> Option<&str> {
    let apex = extract_apex(domain);
    // SLD is the first label of the apex
    apex.split('.').next().filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_IP: IpAddr = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

    fn guard_with_defaults() -> DgaGuard {
        DgaGuard::from_config(&DgaDetectionConfig {
            enabled: true,
            ..Default::default()
        })
    }

    #[test]
    fn disabled_guard_always_returns_clean() {
        let guard = DgaGuard::disabled();
        let result = guard.check("xjk4f9a2h3b5c7d8e.com", TEST_IP);
        assert!(matches!(result, DgaVerdict::Clean));
    }

    #[test]
    fn normal_domain_passes_check() {
        let guard = guard_with_defaults();
        let result = guard.check("google.com", TEST_IP);
        assert!(matches!(result, DgaVerdict::Clean));
    }

    #[test]
    fn short_sld_skipped() {
        let guard = guard_with_defaults();
        let result = guard.check("go.com", TEST_IP);
        assert!(matches!(result, DgaVerdict::Clean));
    }

    #[test]
    fn multi_signal_dga_domain_triggers_detection_with_correct_top_signal() {
        let guard = guard_with_defaults();
        // Random-looking domain: high entropy + high consonant ratio + digits
        let result = guard.check("xjk4f9a2h3b5c7d.com", TEST_IP);
        match result {
            DgaVerdict::Detected {
                signal,
                measured,
                threshold,
            } => {
                assert!(
                    [
                        "sld_entropy",
                        "consonant_ratio",
                        "digit_ratio",
                        "sld_length"
                    ]
                    .contains(&signal),
                    "unexpected signal: {signal}"
                );
                assert!(
                    measured > threshold,
                    "measured ({measured}) should exceed threshold ({threshold})"
                );
            }
            DgaVerdict::Clean => panic!("DGA domain should be detected"),
        }
    }

    #[test]
    fn single_high_entropy_domain_not_blocked() {
        // SLD "aeioubcdf" has high entropy (3.17) but normal consonant ratio (5/9 = 0.56)
        // and zero digits — only entropy can fire, which alone (0.30) < threshold (0.40)
        let guard = DgaGuard::from_config(&DgaDetectionConfig {
            enabled: true,
            sld_entropy_threshold: 3.0,
            ..Default::default()
        });
        let result = guard.check("aeioubcdf.com", TEST_IP);
        assert!(
            matches!(result, DgaVerdict::Clean),
            "Single-signal domain should NOT be blocked"
        );
    }

    #[test]
    fn legitimate_cdn_domains_pass() {
        let guard = guard_with_defaults();
        for domain in &[
            "cloudflare.com",
            "fastly.net",
            "gstatic.com",
            "fbcdn.net",
            "twimg.com",
            "githubusercontent.com",
            "akamaized.net",
        ] {
            let result = guard.check(domain, TEST_IP);
            assert!(
                matches!(result, DgaVerdict::Clean),
                "{domain} should NOT be blocked"
            );
        }
    }

    #[test]
    fn long_sld_alone_does_not_trigger() {
        // Long but repetitive SLD — only sld_length fires (0.25 < 0.40)
        let guard = guard_with_defaults();
        let domain = format!("{}.com", "a".repeat(25));
        let result = guard.check(&domain, TEST_IP);
        assert!(
            matches!(result, DgaVerdict::Clean),
            "Single sld_length signal should not trigger"
        );
    }

    #[test]
    fn long_random_sld_triggers_detection() {
        let guard = guard_with_defaults();
        // Long + high entropy + consonant-heavy → multiple signals
        let domain = format!("{}xbkrwtplmqzncdf.com", "r".repeat(10));
        let result = guard.check(&domain, TEST_IP);
        assert!(
            matches!(result, DgaVerdict::Detected { .. }),
            "Long random SLD should be detected via multiple signals"
        );
    }

    #[test]
    fn two_signals_trigger_detection_at_default_threshold() {
        let guard = guard_with_defaults();
        // All consonants → high entropy (3.9) + consonant ratio 1.0 → 0.30 + 0.25 = 0.55 >= 0.40
        let result = guard.check("bcdfghjklmnpqrst.com", TEST_IP);
        assert!(matches!(result, DgaVerdict::Detected { .. }));
    }

    #[test]
    fn from_config_disabled_never_triggers() {
        let guard = DgaGuard::from_config(&DgaDetectionConfig {
            enabled: false,
            ..Default::default()
        });
        let result = guard.check("xjk4f9a2h3b5c7d8e.com", TEST_IP);
        assert!(matches!(result, DgaVerdict::Clean));
    }

    #[test]
    fn whitelisted_domain_passes_check() {
        let guard = DgaGuard::from_config(&DgaDetectionConfig {
            enabled: true,
            domain_whitelist: vec!["xjk4f9a2h3b5c7d.com".to_string()],
            ..Default::default()
        });
        let result = guard.check("xjk4f9a2h3b5c7d.com", TEST_IP);
        assert!(matches!(result, DgaVerdict::Clean));
    }

    #[test]
    fn whitelisted_client_passes_check() {
        let guard = DgaGuard::from_config(&DgaDetectionConfig {
            enabled: true,
            client_whitelist: vec!["192.168.1.0/24".to_string()],
            ..Default::default()
        });
        let result = guard.check("xjk4f9a2h3b5c7d.com", TEST_IP);
        assert!(matches!(result, DgaVerdict::Clean));
    }

    #[test]
    fn extract_sld_basic() {
        assert_eq!(extract_sld("example.com"), Some("example"));
        assert_eq!(extract_sld("sub.example.com"), Some("example"));
        assert_eq!(extract_sld("example.co.uk"), Some("example"));
        assert_eq!(extract_sld("xjk4f9a2h.com"), Some("xjk4f9a2h"));
    }

    #[test]
    fn shannon_entropy_low_for_repetitive() {
        let e = shannon_entropy(b"aaaa");
        assert!(e < 1.0);
    }

    #[test]
    fn shannon_entropy_high_for_random() {
        let e = shannon_entropy(b"xjk4f9a2h3b5c7d");
        assert!(e > 3.0);
    }
}
