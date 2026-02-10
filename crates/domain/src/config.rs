use serde::{Deserialize, Serialize};

/// Local DNS record for static hostname resolution
///
/// Provides static IP address mapping for local hostnames without requiring
/// a full DNS zone file. Records are cached permanently in memory for instant
/// resolution (<0.1ms) without database queries.
///
/// Use cases:
/// - Home network devices (NAS, printers, IoT)
/// - Development environments (local services, databases)
/// - Static server infrastructure
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LocalDnsRecord {
    /// Hostname (e.g., "nas", "server", "printer")
    /// Will be combined with domain to form FQDN
    pub hostname: String,

    /// Optional domain override (e.g., "home.lan", "lab.local")
    /// If None, uses DnsConfig.local_domain
    /// If both None, uses hostname as-is
    #[serde(default)]
    pub domain: Option<String>,

    /// IP address (IPv4 or IPv6)
    /// Examples: "192.168.1.100", "10.0.0.50", "2001:db8::1"
    pub ip: String,

    /// Record type: "A" for IPv4, "AAAA" for IPv6
    pub record_type: String,

    /// Time-to-live in seconds (optional, default 300)
    /// Used for cache metadata, but local records never expire from cache
    #[serde(default)]
    pub ttl: Option<u32>,
}

impl LocalDnsRecord {
    /// Build fully qualified domain name from hostname and domain
    ///
    /// # Examples
    /// ```
    /// // With custom domain
    /// let record = LocalDnsRecord {
    ///     hostname: "nas".into(),
    ///     domain: Some("lab.local".into()),
    ///     ..
    /// };
    /// assert_eq!(record.fqdn(&None), "nas.lab.local");
    ///
    /// // With default domain
    /// let record = LocalDnsRecord {
    ///     hostname: "server".into(),
    ///     domain: None,
    ///     ..
    /// };
    /// assert_eq!(record.fqdn(&Some("home.lan".into())), "server.home.lan");
    ///
    /// // No domain
    /// let record = LocalDnsRecord {
    ///     hostname: "localhost".into(),
    ///     domain: None,
    ///     ..
    /// };
    /// assert_eq!(record.fqdn(&None), "localhost");
    /// ```
    pub fn fqdn(&self, default_domain: &Option<String>) -> String {
        if let Some(ref domain) = self.domain {
            // Record has explicit domain
            format!("{}.{}", self.hostname, domain)
        } else if let Some(ref default) = default_domain {
            // Use default domain from config
            format!("{}.{}", self.hostname, default)
        } else {
            // No domain - use hostname as-is
            self.hostname.clone()
        }
    }

    /// Get TTL with default fallback
    pub fn ttl_or_default(&self) -> u32 {
        self.ttl.unwrap_or(300)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub server: ServerConfig,
    pub dns: DnsConfig,
    pub blocking: BlockingConfig,
    pub logging: LoggingConfig,
    pub database: DatabaseConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub dns_port: u16,
    pub web_port: u16,
    pub bind_address: String,
}

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

    #[serde(default = "default_upstream_strategy")]
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
    #[serde(default = "default_cache_lazy_expiration")]
    pub cache_lazy_expiration: bool,
    #[serde(default = "default_cache_compaction_interval")]
    pub cache_compaction_interval: u64,
    #[serde(default = "default_cache_adaptive_thresholds")]
    pub cache_adaptive_thresholds: bool,

    // ============================================================================
    // QUERY FILTERS (Fase 1 - Privacy)
    // ============================================================================
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

    // ============================================================================
    // CONDITIONAL FORWARDING (Fase 3)
    // ============================================================================
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

    // ============================================================================
    // LOCAL DNS RECORDS (Fase 4)
    // ============================================================================
    /// Static hostname → IP mappings cached permanently in memory
    /// These records are preloaded on server startup and never expire from cache
    /// Changes require editing this config file and restarting (or using Web UI)
    #[serde(default)]
    pub local_records: Vec<LocalDnsRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UpstreamPool {
    pub name: String,

    #[serde(default = "default_upstream_strategy")]
    pub strategy: UpstreamStrategy,

    #[serde(default = "default_priority")]
    pub priority: u8,

    pub servers: Vec<String>,

    #[serde(default)]
    pub weight: Option<u32>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamStrategy {
    Parallel,
    Balanced,
    Failover,
}

impl UpstreamStrategy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Parallel => "parallel",
            Self::Balanced => "balanced",
            Self::Failover => "failover",
        }
    }
}

impl Default for UpstreamStrategy {
    fn default() -> Self {
        Self::Parallel
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HealthCheckConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_health_check_interval")]
    pub interval_seconds: u64,

    #[serde(default = "default_health_check_timeout")]
    pub timeout_ms: u64,

    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u8,

    #[serde(default = "default_success_threshold")]
    pub success_threshold: u8,
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_seconds: 30,
            timeout_ms: 2000,
            failure_threshold: 3,
            success_threshold: 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BlockingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub custom_blocked: Vec<String>,
    #[serde(default)]
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    #[serde(default = "default_db_path")]
    pub path: String,
    #[serde(default = "default_true")]
    pub log_queries: bool,
}

fn default_query_timeout() -> u64 {
    5
}
fn default_cache_ttl() -> u32 {
    3600
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_db_path() -> String {
    "ferrous-dns.db".to_string()
}
fn default_true() -> bool {
    true
}
fn default_false() -> bool {
    false
}
fn default_upstream_strategy() -> UpstreamStrategy {
    UpstreamStrategy::Parallel
}
fn default_priority() -> u8 {
    1
}
fn default_health_check_interval() -> u64 {
    30
}
fn default_health_check_timeout() -> u64 {
    2000
}
fn default_failure_threshold() -> u8 {
    3
}
fn default_success_threshold() -> u8 {
    2
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

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                dns_port: 53,
                web_port: 8080,
                bind_address: "0.0.0.0".to_string(),
            },
            dns: DnsConfig {
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

                // Query filters
                block_private_ptr: true,
                block_non_fqdn: false,
                local_domain: None,

                // Conditional forwarding (Fase 3)
                conditional_forwarding: vec![],
                conditional_forward_network: None,
                conditional_forward_router: None,

                // Local DNS records (Fase 4)
                local_records: vec![],
            },
            blocking: BlockingConfig {
                enabled: true,
                custom_blocked: vec![],
                whitelist: vec![],
            },
            logging: LoggingConfig {
                level: default_log_level(),
            },
            database: DatabaseConfig {
                path: default_db_path(),
                log_queries: true,
            },
        }
    }
}

impl Config {
    pub fn load(path: Option<&str>, cli_overrides: CliOverrides) -> Result<Self, ConfigError> {
        let mut config = if let Some(path) = path {
            Self::from_file(path)?
        } else {
            if std::path::Path::new("ferrous-dns.toml").exists() {
                Self::from_file("ferrous-dns.toml")?
            } else if std::path::Path::new("/etc/ferrous-dns/config.toml").exists() {
                Self::from_file("/etc/ferrous-dns/config.toml")?
            } else {
                Self::default()
            }
        };

        config.apply_cli_overrides(cli_overrides);
        config.normalize_pools();
        Ok(config)
    }

    fn from_file(path: &str) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::FileRead(path.to_string(), e.to_string()))?;
        toml::from_str(&contents).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    fn apply_cli_overrides(&mut self, overrides: CliOverrides) {
        if let Some(port) = overrides.dns_port {
            self.server.dns_port = port;
        }
        if let Some(port) = overrides.web_port {
            self.server.web_port = port;
        }
        if let Some(bind) = overrides.bind_address {
            self.server.bind_address = bind;
        }
        if let Some(db) = overrides.database_path {
            self.database.path = db;
        }
        if let Some(level) = overrides.log_level {
            self.logging.level = level;
        }
    }

    fn normalize_pools(&mut self) {
        if self.dns.pools.is_empty() && !self.dns.upstream_servers.is_empty() {
            self.dns.pools.push(UpstreamPool {
                name: "default".to_string(),
                strategy: self.dns.default_strategy,
                priority: 1,
                servers: self.dns.upstream_servers.clone(),
                weight: None,
            });
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.dns_port == 0 {
            return Err(ConfigError::Validation("DNS port cannot be 0".to_string()));
        }

        if self.dns.pools.is_empty() && self.dns.upstream_servers.is_empty() {
            return Err(ConfigError::Validation(
                "No upstream servers configured".to_string(),
            ));
        }

        for pool in &self.dns.pools {
            if pool.servers.is_empty() {
                return Err(ConfigError::Validation(format!(
                    "Pool '{}' has no servers",
                    pool.name
                )));
            }
        }

        Ok(())
    }

    pub fn save(&self, path: &str) -> Result<(), ConfigError> {
        let toml_string = toml::to_string_pretty(self)
            .map_err(|e| ConfigError::Parse(format!("Failed to serialize config: {}", e)))?;
        std::fs::write(path, toml_string)
            .map_err(|e| ConfigError::FileWrite(path.to_string(), e.to_string()))?;
        Ok(())
    }

    pub fn get_config_path() -> Option<String> {
        if std::path::Path::new("ferrous-dns.toml").exists() {
            Some("ferrous-dns.toml".to_string())
        } else if std::path::Path::new("/etc/ferrous-dns/config.toml").exists() {
            Some("/etc/ferrous-dns/config.toml".to_string())
        } else {
            None
        }
    }
}

#[derive(Debug, Default)]
pub struct CliOverrides {
    pub dns_port: Option<u16>,
    pub web_port: Option<u16>,
    pub bind_address: Option<String>,
    pub database_path: Option<String>,
    pub log_level: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Failed to read config file {0}: {1}")]
    FileRead(String, String),
    #[error("Failed to write config file {0}: {1}")]
    FileWrite(String, String),
    #[error("Failed to parse config: {0}")]
    Parse(String),
    #[error("Configuration validation error: {0}")]
    Validation(String),
}
