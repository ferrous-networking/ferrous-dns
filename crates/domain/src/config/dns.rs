use serde::{Deserialize, Serialize};

use super::health::HealthCheckConfig;
use super::local_records::LocalDnsRecord;
use super::upstream::UpstreamPool;
use super::upstream::UpstreamStrategy;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConditionalForward {
    pub domain: String,

    pub server: String,

    #[serde(default)]
    pub record_types: Option<Vec<String>>,
}

impl ConditionalForward {
    pub fn matches_domain(&self, query_domain: &str) -> bool {
        let query_lower = query_domain.to_lowercase();
        let rule_lower = self.domain.to_lowercase();

        if query_lower == rule_lower {
            return true;
        }

        query_lower.ends_with(&format!(".{}", rule_lower))
    }

    pub fn matches_record_type(&self, record_type: &str) -> bool {
        match &self.record_types {
            None => true,
            Some(types) => types.iter().any(|t| t.eq_ignore_ascii_case(record_type)),
        }
    }

    pub fn matches(&self, query_domain: &str, record_type: &str) -> bool {
        self.matches_domain(query_domain) && self.matches_record_type(record_type)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    #[serde(default)]
    pub upstream_servers: Vec<String>,

    #[serde(default = "default_query_timeout")]
    pub query_timeout: u64,

    #[serde(default = "default_true")]
    pub cache_enabled: bool,

    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u32,

    #[serde(default = "default_false")]
    pub dnssec_enabled: bool,

    #[serde(default)]
    pub default_strategy: UpstreamStrategy,

    #[serde(default)]
    pub pools: Vec<UpstreamPool>,

    #[serde(default)]
    pub health_check: HealthCheckConfig,

    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: usize,
    #[serde(default = "default_cache_eviction_strategy")]
    pub cache_eviction_strategy: String,
    #[serde(default = "default_cache_optimistic_refresh")]
    pub cache_optimistic_refresh: bool,
    #[serde(default = "default_cache_min_hit_rate")]
    pub cache_min_hit_rate: f64,
    #[serde(default = "default_cache_min_frequency")]
    pub cache_min_frequency: u64,
    #[serde(default = "default_cache_min_lfuk_score")]
    pub cache_min_lfuk_score: f64,
    #[serde(default = "default_cache_refresh_threshold")]
    pub cache_refresh_threshold: f64,
    #[serde(default = "default_cache_lfuk_history_size")]
    pub cache_lfuk_history_size: usize,
    #[serde(default = "default_cache_batch_eviction_percentage")]
    pub cache_batch_eviction_percentage: f64,
    #[serde(default = "default_cache_compaction_interval")]
    pub cache_compaction_interval: u64,
    #[serde(default = "default_cache_adaptive_thresholds")]
    pub cache_adaptive_thresholds: bool,

    #[serde(default = "default_cache_shard_amount")]
    pub cache_shard_amount: usize,

    #[serde(default = "default_cache_access_window_secs")]
    pub cache_access_window_secs: u64,

    #[serde(default = "default_cache_eviction_sample_size")]
    pub cache_eviction_sample_size: usize,

    #[serde(default = "default_true")]
    pub block_private_ptr: bool,

    #[serde(default = "default_false")]
    pub block_non_fqdn: bool,

    #[serde(default)]
    pub local_domain: Option<String>,

    #[serde(default)]
    pub conditional_forwarding: Vec<ConditionalForward>,

    #[serde(default)]
    pub local_records: Vec<LocalDnsRecord>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            upstream_servers: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            query_timeout: default_query_timeout(),
            cache_enabled: true,
            cache_ttl: default_cache_ttl(),
            dnssec_enabled: false,
            default_strategy: UpstreamStrategy::Parallel,
            pools: vec![],
            health_check: HealthCheckConfig::default(),
            cache_max_entries: default_cache_max_entries(),
            cache_eviction_strategy: default_cache_eviction_strategy(),
            cache_optimistic_refresh: default_cache_optimistic_refresh(),
            cache_min_hit_rate: default_cache_min_hit_rate(),
            cache_min_frequency: default_cache_min_frequency(),
            cache_min_lfuk_score: default_cache_min_lfuk_score(),
            cache_refresh_threshold: default_cache_refresh_threshold(),
            cache_lfuk_history_size: default_cache_lfuk_history_size(),
            cache_batch_eviction_percentage: default_cache_batch_eviction_percentage(),
            cache_compaction_interval: default_cache_compaction_interval(),
            cache_adaptive_thresholds: default_cache_adaptive_thresholds(),
            cache_shard_amount: default_cache_shard_amount(),
            cache_access_window_secs: default_cache_access_window_secs(),
            cache_eviction_sample_size: default_cache_eviction_sample_size(),
            block_private_ptr: true,
            block_non_fqdn: false,
            local_domain: None,
            conditional_forwarding: vec![],
            local_records: vec![],
        }
    }
}

fn default_query_timeout() -> u64 {
    2000
}

fn default_cache_ttl() -> u32 {
    3600
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

fn default_cache_max_entries() -> usize {
    200_000
}

fn default_cache_eviction_strategy() -> String {
    "hit_rate".to_string()
}

fn default_cache_optimistic_refresh() -> bool {
    true
}

fn default_cache_min_hit_rate() -> f64 {
    2.0
}

fn default_cache_min_frequency() -> u64 {
    10
}

fn default_cache_min_lfuk_score() -> f64 {
    1.5
}

fn default_cache_refresh_threshold() -> f64 {
    0.75
}

fn default_cache_lfuk_history_size() -> usize {
    10
}

fn default_cache_batch_eviction_percentage() -> f64 {
    0.1
}

fn default_cache_compaction_interval() -> u64 {
    300
}

fn default_cache_adaptive_thresholds() -> bool {
    false
}

fn default_cache_access_window_secs() -> u64 {
    7200
}

fn default_cache_eviction_sample_size() -> usize {
    8
}

fn default_cache_shard_amount() -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    (cpus * 4).next_power_of_two().clamp(8, 256)
}
