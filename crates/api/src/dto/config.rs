use serde::{Deserialize, Serialize};

#[derive(Serialize, Debug, Clone)]
pub struct ConfigResponse {
    pub server: ServerConfigResponse,
    pub dns: DnsConfigResponse,
    pub blocking: BlockingConfigResponse,
    pub logging: LoggingConfigResponse,
    pub database: DatabaseConfigResponse,
    pub config_path: Option<String>,
    pub writable: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct ServerConfigResponse {
    pub dns_port: u16,
    pub web_port: u16,
    pub bind_address: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct DnsConfigResponse {
    pub upstream_servers: Vec<String>,
    pub pools: Vec<UpstreamPoolResponse>,
    pub health_check: HealthCheckResponse,
    pub query_timeout: u64,
    pub cache_enabled: bool,
    pub cache_ttl: u32,
    pub dnssec_enabled: bool,
    pub cache_eviction_strategy: String,
    pub cache_max_entries: usize,
    pub cache_min_hit_rate: f64,
    pub cache_min_frequency: u64,
    pub cache_min_lfuk_score: f64,
    pub cache_compaction_interval: u64,
    pub cache_refresh_threshold: f64,
    pub cache_optimistic_refresh: bool,
    pub cache_adaptive_thresholds: bool,
    pub cache_access_window_secs: u64,
    pub block_non_fqdn: bool,
    pub block_private_ptr: bool,
    pub local_domain: Option<String>,
    pub conditional_forwarding: Vec<ConditionalForwardingResponse>,
}

#[derive(Serialize, Debug, Clone)]
pub struct ConditionalForwardingResponse {
    pub domain: String,
    pub server: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct UpstreamPoolResponse {
    pub name: String,
    pub strategy: String,
    pub priority: u8,
    pub servers: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct HealthCheckResponse {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u8,
    pub success_threshold: u8,
}

#[derive(Serialize, Debug, Clone)]
pub struct BlockingConfigResponse {
    pub enabled: bool,
    pub custom_blocked: Vec<String>,
    pub whitelist: Vec<String>,
}

#[derive(Serialize, Debug, Clone)]
pub struct LoggingConfigResponse {
    pub level: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct DatabaseConfigResponse {
    pub path: String,
    pub log_queries: bool,
}

#[derive(Deserialize, Debug)]
pub struct UpdateConfigRequest {
    pub dns: Option<DnsConfigUpdate>,
    pub blocking: Option<BlockingConfigUpdate>,
}

#[derive(Deserialize, Debug)]
pub struct DnsConfigUpdate {
    pub upstream_servers: Option<Vec<String>>,
    pub cache_enabled: Option<bool>,
    pub dnssec_enabled: Option<bool>,
    pub cache_eviction_strategy: Option<String>,
    pub cache_max_entries: Option<usize>,
    pub cache_min_hit_rate: Option<f64>,
    pub cache_min_frequency: Option<u64>,
    pub cache_min_lfuk_score: Option<f64>,
    pub cache_compaction_interval: Option<u64>,
    pub cache_refresh_threshold: Option<f64>,
    pub cache_optimistic_refresh: Option<bool>,
    pub cache_adaptive_thresholds: Option<bool>,
    pub cache_access_window_secs: Option<u64>,
    pub block_non_fqdn: Option<bool>,
    pub block_private_ptr: Option<bool>,
    pub local_domain: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct BlockingConfigUpdate {
    pub enabled: Option<bool>,
    pub custom_blocked: Option<Vec<String>>,
    pub whitelist: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsDto {
    pub never_forward_non_fqdn: bool,

    pub never_forward_reverse_lookups: bool,

    pub conditional_forwarding_enabled: bool,

    #[serde(default)]
    pub local_domain: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SettingsUpdateResponse {
    pub success: bool,
    pub message: String,
    pub settings: SettingsDto,
}

impl From<ConfigResponse> for SettingsDto {
    fn from(config: ConfigResponse) -> Self {
        SettingsDto {
            never_forward_non_fqdn: config.dns.block_non_fqdn,
            never_forward_reverse_lookups: config.dns.block_private_ptr,
            conditional_forwarding_enabled: !config.dns.conditional_forwarding.is_empty(),
            local_domain: config.dns.local_domain.unwrap_or_default(),
        }
    }
}
