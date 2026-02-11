use serde::{Deserialize, Serialize};

use super::health::HealthCheckConfig;
use super::local_records::LocalDnsRecord;
use super::upstream::UpstreamPool;
use super::upstream::UpstreamStrategy;

/// Conditional forwarding rule for domain-specific DNS servers
///
/// Routes queries for specific domains to designated DNS servers instead of
/// using the default upstream pools. Useful for:
/// - Local network domains (*.home.lan → router DHCP server)
/// - Corporate domains (*.corp.local → corporate DNS)
/// - Development environments (*.dev.local → local DNS)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ConditionalForward {
    /// Domain pattern to match (e.g., "home.lan", "corp.local")
    /// Matches both exact domain and all subdomains (*.domain)
    pub domain: String,

    /// DNS server to forward queries to (e.g., "192.168.1.1:53")
    pub server: String,

    /// Optional: Specific record types to forward (e.g., ["A", "AAAA"])
    /// If None, forwards all record types
    #[serde(default)]
    pub record_types: Option<Vec<String>>,
}

impl ConditionalForward {
    /// Check if a query domain matches this forwarding rule
    ///
    /// Matches both exact domain and all subdomains.
    /// Examples:
    /// - Rule "home.lan" matches: "home.lan", "nas.home.lan", "server.home.lan"
    /// - Rule "home.lan" does NOT match: "otherhome.lan", "google.com"
    pub fn matches_domain(&self, query_domain: &str) -> bool {
        let query_lower = query_domain.to_lowercase();
        let rule_lower = self.domain.to_lowercase();

        // Exact match
        if query_lower == rule_lower {
            return true;
        }

        // Subdomain match (query ends with .domain)
        query_lower.ends_with(&format!(".{}", rule_lower))
    }

    /// Check if a record type should be forwarded
    ///
    /// Returns true if:
    /// - No record_types filter is set (forward all types), OR
    /// - The query's record type is in the allowed list
    pub fn matches_record_type(&self, record_type: &str) -> bool {
        match &self.record_types {
            None => true, // No filter = forward all types
            Some(types) => types.iter().any(|t| t.eq_ignore_ascii_case(record_type)),
        }
    }

    /// Check if this rule matches a query (domain + record type)
    pub fn matches(&self, query_domain: &str, record_type: &str) -> bool {
        self.matches_domain(query_domain) && self.matches_record_type(record_type)
    }
}

/// DNS resolution configuration
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

    // Cache configuration
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
    #[serde(default = "default_cache_lazy_expiration")]
    pub cache_lazy_expiration: bool,
    #[serde(default = "default_cache_compaction_interval")]
    pub cache_compaction_interval: u64,
    #[serde(default = "default_cache_adaptive_thresholds")]
    pub cache_adaptive_thresholds: bool,

    // Query filters
    /// Block reverse lookups (PTR queries) for private IP ranges
    /// This prevents leaking internal network topology to upstream DNS servers
    #[serde(default = "default_true")]
    pub block_private_ptr: bool,

    /// Block non-FQDN queries (queries without a domain, e.g., "nas", "servidor")
    /// When enabled, only fully qualified domain names are forwarded to upstream
    #[serde(default = "default_false")]
    pub block_non_fqdn: bool,

    /// Local domain to append to non-FQDN queries (e.g., "home.lan")
    /// This is used for local hostname resolution
    #[serde(default)]
    pub local_domain: Option<String>,

    // Conditional forwarding
    /// Forward queries for specific domains to specific DNS servers
    /// Example: Forward all *.home.lan queries to router at 192.168.1.1
    #[serde(default)]
    pub conditional_forwarding: Vec<ConditionalForward>,

    /// Simplified conditional forwarding for Pi-hole-style UI
    /// Local network in CIDR notation (e.g., "192.168.0.0/24")
    /// When set with conditional_forward_router, automatically creates forwarding rule
    #[serde(default)]
    pub conditional_forward_network: Option<String>,

    /// Router/DHCP server IP address (e.g., "192.168.0.1")
    /// Used as the DNS server for conditional forwarding
    #[serde(default)]
    pub conditional_forward_router: Option<String>,

    // Local DNS records
    /// Static hostname → IP mappings cached permanently in memory
    /// These records are preloaded on server startup and never expire from cache
    /// Changes require editing this config file and restarting (or using Web UI)
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
            cache_lazy_expiration: default_cache_lazy_expiration(),
            cache_compaction_interval: default_cache_compaction_interval(),
            cache_adaptive_thresholds: default_cache_adaptive_thresholds(),
            block_private_ptr: true,
            block_non_fqdn: false,
            local_domain: None,
            conditional_forwarding: vec![],
            conditional_forward_network: None,
            conditional_forward_router: None,
            local_records: vec![],
        }
    }
}

// Default functions for DNS config
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

fn default_cache_lazy_expiration() -> bool {
    true
}

fn default_cache_compaction_interval() -> u64 {
    300
}

fn default_cache_adaptive_thresholds() -> bool {
    false
}
