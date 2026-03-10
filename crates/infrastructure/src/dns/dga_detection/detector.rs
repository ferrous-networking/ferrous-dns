use super::ngram::bigram_deviation_score;
use crate::dns::tunneling::entropy::{extract_apex, shannon_entropy};
use dashmap::DashMap;
use ferrous_dns_application::ports::DgaFlagStore;
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_application::use_cases::dns::DgaAnalysisEvent;
use ferrous_dns_domain::DgaDetectionConfig;
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const CHANNEL_CAPACITY: usize = 4096;
const WINDOW_DURATION_NS: u64 = 60_000_000_000; // 1 minute
/// Flagged domains live this many times longer than stats entries before eviction.
const FLAGGED_DOMAIN_TTL_MULTIPLIER: u64 = 2;

/// Signal weights for DGA confidence scoring.
const WEIGHT_SLD_ENTROPY: f32 = 0.25;
const WEIGHT_CONSONANT_RATIO: f32 = 0.15;
const WEIGHT_DIGIT_RATIO: f32 = 0.15;
const WEIGHT_SLD_LENGTH: f32 = 0.10;
const WEIGHT_NGRAM_SCORE: f32 = 0.25;
const WEIGHT_DGA_RATE: f32 = 0.10;

/// Per-client DGA tracking statistics.
struct ClientDgaStats {
    dga_domain_count: AtomicU32,
    last_seen_ns: AtomicU64,
    window_start_ns: AtomicU64,
}

impl ClientDgaStats {
    fn new(now_ns: u64) -> Self {
        Self {
            dga_domain_count: AtomicU32::new(0),
            last_seen_ns: AtomicU64::new(now_ns),
            window_start_ns: AtomicU64::new(now_ns),
        }
    }

    fn reset_window(&self, now_ns: u64) {
        self.dga_domain_count.store(0, Ordering::Relaxed);
        self.window_start_ns.store(now_ns, Ordering::Relaxed);
    }
}

/// Alert persisted when a domain is flagged as DGA.
#[allow(dead_code)]
struct DgaAlert {
    signal: String,
    measured_value: f32,
    threshold: f32,
    confidence: f32,
    timestamp_ns: u64,
}

/// Background DGA detector.
///
/// Consumes `DgaAnalysisEvent`s from the hot path via an mpsc channel,
/// computes weighted confidence scores using entropy, character ratios,
/// n-gram analysis, and per-client DGA rate, and flags domains when
/// the confidence exceeds the configured threshold.
pub struct DgaDetector {
    config: DgaDetectionConfig,
    /// Per-client subnet stats: DGA domain count per time window.
    stats: DashMap<u64, ClientDgaStats, FxBuildHasher>,
    /// Domains flagged as DGA by background analysis.
    flagged_domains: DashMap<Arc<str>, DgaAlert, FxBuildHasher>,
}

impl DgaDetector {
    /// Creates a detector and returns the sender/receiver halves of the analysis channel.
    pub fn new(
        config: &DgaDetectionConfig,
    ) -> (
        Self,
        mpsc::Sender<DgaAnalysisEvent>,
        mpsc::Receiver<DgaAnalysisEvent>,
    ) {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let detector = Self {
            config: config.clone(),
            stats: DashMap::with_hasher(FxBuildHasher),
            flagged_domains: DashMap::with_hasher(FxBuildHasher),
        };
        (detector, tx, rx)
    }

    /// Returns the configured stale entry TTL in seconds.
    pub fn stale_entry_ttl_secs(&self) -> u64 {
        self.config.stale_entry_ttl_secs
    }

    /// Removes stale entries older than `stale_entry_ttl_secs`.
    pub fn evict_stale(&self) {
        let now_ns = coarse_now_ns();
        let ttl_ns = self.config.stale_entry_ttl_secs * 1_000_000_000;
        let before = self.stats.len();
        self.stats
            .retain(|_, stats| now_ns - stats.last_seen_ns.load(Ordering::Relaxed) < ttl_ns);
        let evicted = before.saturating_sub(self.stats.len());

        let flagged_before = self.flagged_domains.len();
        self.flagged_domains.retain(|_, alert| {
            now_ns - alert.timestamp_ns < ttl_ns * FLAGGED_DOMAIN_TTL_MULTIPLIER
        });
        let flagged_evicted = flagged_before.saturating_sub(self.flagged_domains.len());

        if evicted > 0 || flagged_evicted > 0 {
            debug!(
                evicted,
                flagged_evicted,
                remaining = self.stats.len(),
                flagged = self.flagged_domains.len(),
                "DGA detector stale eviction"
            );
        }
    }

    /// Runs the background analysis loop, consuming events from the channel.
    pub async fn run_analysis_loop(self: Arc<Self>, mut rx: mpsc::Receiver<DgaAnalysisEvent>) {
        info!("DGA analysis loop started");
        while let Some(event) = rx.recv().await {
            self.process_event(&event);
        }
        info!("DGA analysis loop stopped");
    }

    fn process_event(&self, event: &DgaAnalysisEvent) {
        let apex = extract_apex(&event.domain);
        let sld = match apex.split('.').next() {
            Some(s) if s.len() > 3 => s,
            _ => return,
        };

        let now_ns = coarse_now_ns();
        let subnet_key = subnet_key_from_ip(event.client_ip);

        // Compute signals
        let entropy = shannon_entropy(sld.as_bytes());
        let (consonants, vowels, digits, total) = char_ratios(sld);
        let ngram_score = bigram_deviation_score(sld);

        // Compute weighted confidence
        let mut confidence: f32 = 0.0;
        let mut top_signal = "none";
        let mut top_measured: f32 = 0.0;
        let mut top_threshold: f32 = 0.0;
        let mut top_weight: f32 = 0.0;

        macro_rules! add_signal {
            ($weight:expr, $name:expr, $measured:expr, $threshold:expr) => {
                confidence += $weight;
                if $weight > top_weight {
                    top_weight = $weight;
                    top_signal = $name;
                    top_measured = $measured;
                    top_threshold = $threshold;
                }
            };
        }

        if entropy > self.config.sld_entropy_threshold {
            add_signal!(
                WEIGHT_SLD_ENTROPY,
                "sld_entropy",
                entropy,
                self.config.sld_entropy_threshold
            );
        }

        let alpha = consonants + vowels;
        if alpha > 0 {
            let consonant_ratio = consonants as f32 / alpha as f32;
            if consonant_ratio > self.config.consonant_ratio_threshold {
                add_signal!(
                    WEIGHT_CONSONANT_RATIO,
                    "consonant_ratio",
                    consonant_ratio,
                    self.config.consonant_ratio_threshold
                );
            }
        }

        if total > 0 {
            let digit_ratio = digits as f32 / total as f32;
            if digit_ratio > self.config.digit_ratio_threshold {
                add_signal!(
                    WEIGHT_DIGIT_RATIO,
                    "digit_ratio",
                    digit_ratio,
                    self.config.digit_ratio_threshold
                );
            }
        }

        if sld.len() > self.config.sld_max_length {
            add_signal!(
                WEIGHT_SLD_LENGTH,
                "sld_length",
                sld.len() as f32,
                self.config.sld_max_length as f32
            );
        }

        if ngram_score > self.config.ngram_score_threshold {
            add_signal!(
                WEIGHT_NGRAM_SCORE,
                "ngram_score",
                ngram_score,
                self.config.ngram_score_threshold
            );
        }

        // Track per-client DGA rate
        let entry = self
            .stats
            .entry(subnet_key)
            .or_insert_with(|| ClientDgaStats::new(now_ns));
        let stats = entry.value();

        let window_start = stats.window_start_ns.load(Ordering::Relaxed);
        if now_ns.saturating_sub(window_start) > WINDOW_DURATION_NS
            && stats
                .window_start_ns
                .compare_exchange(window_start, now_ns, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            stats.reset_window(now_ns);
        }
        stats.last_seen_ns.store(now_ns, Ordering::Relaxed);

        // Count this domain toward DGA rate if it has at least one signal
        if confidence > 0.0 {
            let dga_count = stats.dga_domain_count.fetch_add(1, Ordering::Relaxed) + 1;
            if dga_count > self.config.dga_rate_per_client {
                add_signal!(
                    WEIGHT_DGA_RATE,
                    "dga_rate",
                    dga_count as f32,
                    self.config.dga_rate_per_client as f32
                );
            }
        }

        let _ = top_weight;

        if confidence >= self.config.confidence_threshold {
            let apex_arc: Arc<str> = Arc::from(apex);
            self.flagged_domains
                .entry(apex_arc)
                .and_modify(|alert| {
                    alert.timestamp_ns = now_ns;
                    alert.confidence = confidence;
                    alert.measured_value = top_measured;
                })
                .or_insert_with(|| {
                    warn!(
                        domain = apex,
                        signal = top_signal,
                        confidence,
                        measured = top_measured,
                        threshold = top_threshold,
                        "DGA domain detected — domain flagged"
                    );
                    DgaAlert {
                        signal: top_signal.to_string(),
                        measured_value: top_measured,
                        threshold: top_threshold,
                        confidence,
                        timestamp_ns: now_ns,
                    }
                });
        }
    }
}

impl DgaFlagStore for DgaDetector {
    fn is_flagged(&self, domain: &str) -> bool {
        let apex = extract_apex(domain);
        self.flagged_domains.contains_key(apex)
    }
}

impl ferrous_dns_application::ports::DgaEvictionTarget for DgaDetector {
    fn evict_stale(&self) {
        self.evict_stale();
    }

    fn tracked_count(&self) -> usize {
        self.stats.len()
    }

    fn flagged_count(&self) -> usize {
        self.flagged_domains.len()
    }
}

/// Computes character class counts for DGA detection.
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
            _ => {}
        }
    }

    (consonants, vowels, digits, total)
}

/// Computes a subnet key from an IP address.
fn subnet_key_from_ip(ip: IpAddr) -> u64 {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = u32::MAX << (32 - 24); // /24
            (bits & mask) as u64
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = u128::MAX << (128 - 48); // /48
            ((bits & mask) >> 64) as u64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn default_config() -> DgaDetectionConfig {
        DgaDetectionConfig::default()
    }

    #[test]
    fn unknown_domain_not_flagged() {
        let (detector, _tx, _rx) = DgaDetector::new(&default_config());
        assert!(!detector.is_flagged("example.com"));
    }

    #[test]
    fn flagged_domain_detected() {
        let (detector, _tx, _rx) = DgaDetector::new(&default_config());
        let apex: Arc<str> = Arc::from("xjk4f9a2h.com");
        detector.flagged_domains.insert(
            apex,
            DgaAlert {
                signal: "test".to_string(),
                measured_value: 4.0,
                threshold: 3.5,
                confidence: 0.7,
                timestamp_ns: coarse_now_ns(),
            },
        );
        assert!(detector.is_flagged("xjk4f9a2h.com"));
        assert!(detector.is_flagged("sub.xjk4f9a2h.com"));
    }

    #[test]
    fn eviction_removes_stale_entries() {
        let mut config = default_config();
        config.stale_entry_ttl_secs = 0; // immediate expiry
        let (detector, _tx, _rx) = DgaDetector::new(&config);

        detector.stats.insert(
            12345,
            ClientDgaStats {
                dga_domain_count: AtomicU32::new(5),
                last_seen_ns: AtomicU64::new(0), // very old
                window_start_ns: AtomicU64::new(0),
            },
        );

        let apex: Arc<str> = Arc::from("old.com");
        detector.flagged_domains.insert(
            apex,
            DgaAlert {
                signal: "test".to_string(),
                measured_value: 4.0,
                threshold: 3.5,
                confidence: 0.7,
                timestamp_ns: 0,
            },
        );

        assert_eq!(detector.stats.len(), 1);
        assert_eq!(detector.flagged_domains.len(), 1);

        detector.evict_stale();

        assert_eq!(detector.stats.len(), 0);
        assert_eq!(detector.flagged_domains.len(), 0);
    }

    #[test]
    fn eviction_keeps_fresh_entries() {
        let config = default_config();
        let (detector, _tx, _rx) = DgaDetector::new(&config);

        let now = coarse_now_ns();
        detector.stats.insert(
            12345,
            ClientDgaStats {
                dga_domain_count: AtomicU32::new(1),
                last_seen_ns: AtomicU64::new(now),
                window_start_ns: AtomicU64::new(now),
            },
        );

        let apex: Arc<str> = Arc::from("fresh.com");
        detector.flagged_domains.insert(
            apex,
            DgaAlert {
                signal: "test".to_string(),
                measured_value: 4.0,
                threshold: 3.5,
                confidence: 0.7,
                timestamp_ns: now,
            },
        );

        detector.evict_stale();

        assert_eq!(detector.stats.len(), 1);
        assert_eq!(detector.flagged_domains.len(), 1);
    }

    #[test]
    fn tracked_and_flagged_counts() {
        let (detector, _tx, _rx) = DgaDetector::new(&default_config());
        assert_eq!(detector.stats.len(), 0);
        assert_eq!(detector.flagged_domains.len(), 0);

        let now = coarse_now_ns();
        detector.stats.insert(1, ClientDgaStats::new(now));
        detector.stats.insert(2, ClientDgaStats::new(now));
        assert_eq!(detector.stats.len(), 2);
    }

    #[test]
    fn process_event_flags_random_domain() {
        let mut config = default_config();
        config.confidence_threshold = 0.35; // lower for test
        let (detector, _tx, _rx) = DgaDetector::new(&config);

        let event = DgaAnalysisEvent {
            domain: Arc::from("xjk4f9a2h3b5c7d.com"),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        detector.process_event(&event);
        assert!(
            detector.is_flagged("xjk4f9a2h3b5c7d.com"),
            "Random-looking domain should be flagged"
        );
    }

    #[test]
    fn process_event_does_not_flag_normal_domain() {
        let (detector, _tx, _rx) = DgaDetector::new(&default_config());

        let event = DgaAnalysisEvent {
            domain: Arc::from("google.com"),
            client_ip: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
        };

        detector.process_event(&event);
        assert!(
            !detector.is_flagged("google.com"),
            "Normal domain should not be flagged"
        );
    }
}
