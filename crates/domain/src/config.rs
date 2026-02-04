use serde::{Deserialize, Serialize};

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

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    pub upstream_servers: Vec<String>,
    #[serde(default = "default_query_timeout")]
    pub query_timeout: u64,
    #[serde(default = "default_true")]
    pub cache_enabled: bool,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u32,  // Changed from u64 to u32 (consistent with cache implementation)
    #[serde(default = "default_false")]
    pub dnssec_enabled: bool,
    
    // Cache size
    #[serde(default = "default_cache_max_entries")]
    pub cache_max_entries: usize,
    
    // Eviction strategy
    #[serde(default = "default_cache_eviction_strategy")]
    pub cache_eviction_strategy: String,
    
    // Optimistic refresh
    #[serde(default = "default_cache_optimistic_refresh")]
    pub cache_optimistic_refresh: bool,
    
    // Minimum thresholds per strategy
    #[serde(default = "default_cache_min_hit_rate")]
    pub cache_min_hit_rate: f64,
    
    #[serde(default = "default_cache_min_frequency")]
    pub cache_min_frequency: u64,
    
    #[serde(default = "default_cache_min_lfuk_score")]
    pub cache_min_lfuk_score: f64,
    
    // Refresh threshold
    #[serde(default = "default_cache_refresh_threshold")]
    pub cache_refresh_threshold: f64,
    
    // LFU-K specific
    #[serde(default = "default_cache_lfuk_history_size")]
    pub cache_lfuk_history_size: usize,
    
    // Performance optimizations
    #[serde(default = "default_cache_batch_eviction_percentage")]
    pub cache_batch_eviction_percentage: f64,
    
    #[serde(default = "default_cache_lazy_expiration")]
    pub cache_lazy_expiration: bool,
    
    #[serde(default = "default_cache_compaction_interval")]
    pub cache_compaction_interval: u64,
    
    #[serde(default = "default_cache_adaptive_thresholds")]
    pub cache_adaptive_thresholds: bool,
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

fn default_query_timeout() -> u64 { 5 }
fn default_cache_ttl() -> u32 { 3600 }
fn default_log_level() -> String { "info".to_string() }
fn default_db_path() -> String { "ferrous-dns.db".to_string() }
fn default_true() -> bool { true }
fn default_false() -> bool { false }

// Cache defaults
fn default_cache_max_entries() -> usize { 200_000 }
fn default_cache_eviction_strategy() -> String { "hit_rate".to_string() }
fn default_cache_optimistic_refresh() -> bool { true }
fn default_cache_min_hit_rate() -> f64 { 2.0 }
fn default_cache_min_frequency() -> u64 { 10 }
fn default_cache_min_lfuk_score() -> f64 { 1.5 }
fn default_cache_refresh_threshold() -> f64 { 0.75 }
fn default_cache_lfuk_history_size() -> usize { 10 }
fn default_cache_batch_eviction_percentage() -> f64 { 0.1 }
fn default_cache_lazy_expiration() -> bool { true }
fn default_cache_compaction_interval() -> u64 { 300 }
fn default_cache_adaptive_thresholds() -> bool { false }

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

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.server.dns_port == 0 {
            return Err(ConfigError::Validation("DNS port cannot be 0".to_string()));
        }
        if self.dns.upstream_servers.is_empty() {
            return Err(ConfigError::Validation("No upstream servers".to_string()));
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
