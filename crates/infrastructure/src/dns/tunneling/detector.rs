use super::client_stats::{
    fx_hash_str, new_stats_map, subnet_key_from_ip, ClientApexStats, StatsMap, TrackingKey,
};
use super::entropy::{extract_apex, extract_subdomain, shannon_entropy};
use dashmap::DashMap;
use ferrous_dns_application::ports::TunnelingFlagStore;
use ferrous_dns_application::use_cases::dns::coarse_timer::coarse_now_ns;
use ferrous_dns_application::use_cases::dns::TunnelingAnalysisEvent;
use ferrous_dns_domain::{RecordType, TunnelingDetectionConfig};
use rustc_hash::FxBuildHasher;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

const CHANNEL_CAPACITY: usize = 4096;
const WINDOW_DURATION_NS: u64 = 60_000_000_000; // 1 minute
/// Flagged domains live this many times longer than stats entries before eviction.
const FLAGGED_DOMAIN_TTL_MULTIPLIER: u64 = 2;

/// Alert persisted when a domain is flagged as a tunneling endpoint.
#[derive(Debug, Clone)]
pub struct TunnelingAlert {
    pub signal: String,
    pub measured_value: f32,
    pub threshold: f32,
    pub confidence: f32,
    pub timestamp_ns: u64,
}

/// Background DNS tunneling detector.
///
/// Consumes `TunnelingAnalysisEvent`s from the hot path via an mpsc channel,
/// maintains per-client/apex statistics, and flags domains when the confidence
/// score exceeds the configured threshold.
pub struct TunnelingDetector {
    config: TunnelingDetectionConfig,
    #[doc(hidden)]
    pub stats: StatsMap,
    #[doc(hidden)]
    pub flagged_domains: DashMap<Arc<str>, TunnelingAlert, FxBuildHasher>,
}

impl TunnelingDetector {
    /// Creates a detector and returns the sender half of the analysis channel.
    pub fn new(
        config: &TunnelingDetectionConfig,
    ) -> (
        Self,
        mpsc::Sender<TunnelingAnalysisEvent>,
        mpsc::Receiver<TunnelingAnalysisEvent>,
    ) {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let detector = Self {
            config: config.clone(),
            stats: new_stats_map(),
            flagged_domains: DashMap::with_hasher(FxBuildHasher),
        };
        (detector, tx, rx)
    }

    /// Returns the number of currently tracked client/apex pairs.
    pub fn tracked_count(&self) -> usize {
        self.stats.len()
    }

    /// Returns the number of currently flagged domains.
    pub fn flagged_count(&self) -> usize {
        self.flagged_domains.len()
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
                "Tunneling detector stale eviction"
            );
        }
    }

    /// Returns the configured stale entry TTL in seconds.
    pub fn stale_entry_ttl_secs(&self) -> u64 {
        self.config.stale_entry_ttl_secs
    }

    /// Runs the background analysis loop, consuming events from the channel.
    pub async fn run_analysis_loop(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<TunnelingAnalysisEvent>,
    ) {
        info!("DNS tunneling analysis loop started");
        while let Some(event) = rx.recv().await {
            self.process_event(&event);
        }
        info!("DNS tunneling analysis loop stopped");
    }

    #[doc(hidden)]
    pub fn process_event(&self, event: &TunnelingAnalysisEvent) {
        let apex = extract_apex(&event.domain);
        let apex_hash = fx_hash_str(apex);
        let subnet = subnet_key_from_ip(event.client_ip, 24, 48);
        let key = TrackingKey { subnet, apex_hash };

        let now_ns = coarse_now_ns();

        let entry = self
            .stats
            .entry(key)
            .or_insert_with(|| ClientApexStats::new(now_ns));
        let stats = entry.value();

        // Reset window if expired — CAS to prevent double-reset race
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
        stats.query_count.fetch_add(1, Ordering::Relaxed);
        stats.total_count.fetch_add(1, Ordering::Relaxed);

        if event.record_type == RecordType::TXT {
            stats.txt_query_count.fetch_add(1, Ordering::Relaxed);
        }

        if event.was_nxdomain {
            stats.nxdomain_count.fetch_add(1, Ordering::Relaxed);
        }

        if let Some(subdomain) = extract_subdomain(&event.domain) {
            let sub_hash = fx_hash_str(subdomain);
            if stats.bloom_add(sub_hash) {
                stats.unique_subdomain_count.fetch_add(1, Ordering::Relaxed);
            }
        }

        let (confidence, top_signal, measured, threshold) =
            self.compute_confidence(stats, &event.domain);

        if confidence >= self.config.confidence_threshold {
            let apex_arc: Arc<str> = Arc::from(apex);
            self.flagged_domains
                .entry(apex_arc)
                .and_modify(|alert| {
                    alert.timestamp_ns = now_ns;
                    alert.confidence = confidence;
                    alert.measured_value = measured;
                })
                .or_insert_with(|| {
                    warn!(
                        domain = apex,
                        signal = top_signal,
                        confidence,
                        measured,
                        threshold,
                        "DNS tunneling detected — domain flagged"
                    );
                    TunnelingAlert {
                        signal: top_signal.to_string(),
                        measured_value: measured,
                        threshold,
                        confidence,
                        timestamp_ns: now_ns,
                    }
                });
        }
    }

    #[doc(hidden)]
    pub fn compute_confidence(
        &self,
        stats: &ClientApexStats,
        domain: &str,
    ) -> (f32, &'static str, f32, f32) {
        let mut score: f32 = 0.0;
        let mut top_weight: f32 = 0.0;
        let mut top_signal = "none";
        let mut top_measured: f32 = 0.0;
        let mut top_threshold: f32 = 0.0;

        // Macro to update top signal when a new signal fires with higher weight
        macro_rules! add_signal {
            ($weight:expr, $name:expr, $measured:expr, $threshold:expr) => {
                score += $weight;
                if $weight > top_weight {
                    top_weight = $weight;
                    top_signal = $name;
                    top_measured = $measured;
                    top_threshold = $threshold;
                }
            };
        }

        if let Some(subdomain) = extract_subdomain(domain) {
            let entropy = shannon_entropy(subdomain.as_bytes());
            if entropy > self.config.entropy_threshold {
                add_signal!(0.30, "entropy", entropy, self.config.entropy_threshold);
            }
        }

        let query_count = stats.query_count.load(Ordering::Relaxed);
        if query_count > self.config.query_rate_per_apex {
            add_signal!(
                0.25,
                "query_rate",
                query_count as f32,
                self.config.query_rate_per_apex as f32
            );
        }

        let unique_count = stats.unique_subdomain_count.load(Ordering::Relaxed);
        if unique_count > self.config.unique_subdomain_threshold {
            add_signal!(
                0.25,
                "unique_subdomains",
                unique_count as f32,
                self.config.unique_subdomain_threshold as f32
            );
        }

        let total = stats.total_count.load(Ordering::Relaxed);
        if total > 0 {
            let txt_count = stats.txt_query_count.load(Ordering::Relaxed);
            let txt_ratio = txt_count as f32 / total as f32;
            if txt_ratio > self.config.txt_proportion_threshold {
                add_signal!(
                    0.10,
                    "txt_proportion",
                    txt_ratio,
                    self.config.txt_proportion_threshold
                );
            }

            let nx_count = stats.nxdomain_count.load(Ordering::Relaxed);
            let nx_ratio = nx_count as f32 / total as f32;
            if nx_ratio > self.config.nxdomain_ratio_threshold {
                add_signal!(
                    0.10,
                    "nxdomain_ratio",
                    nx_ratio,
                    self.config.nxdomain_ratio_threshold
                );
            }
        }

        let _ = top_weight;
        (score, top_signal, top_measured, top_threshold)
    }
}

impl ferrous_dns_application::ports::TunnelingEvictionTarget for TunnelingDetector {
    fn evict_stale(&self) {
        self.evict_stale();
    }

    fn tracked_count(&self) -> usize {
        self.tracked_count()
    }

    fn flagged_count(&self) -> usize {
        self.flagged_count()
    }
}

impl TunnelingFlagStore for TunnelingDetector {
    fn is_flagged(&self, domain: &str) -> bool {
        let apex = extract_apex(domain);
        self.flagged_domains.contains_key(apex)
    }
}
