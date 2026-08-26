use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ConfigResponse {
    pub server: ServerConfigResponse,
    pub dns: DnsConfigResponse,
    pub blocking: BlockingConfigResponse,
    pub dns64: Dns64ConfigResponse,
    pub logging: LoggingConfigResponse,
    pub database: DatabaseConfigResponse,
    pub auth: AuthConfigResponse,
    pub config_path: Option<String>,
    pub writable: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AuthConfigResponse {
    pub enabled: bool,
    pub session_ttl_hours: u32,
    pub remember_me_days: u32,
    pub login_rate_limit_attempts: u32,
    pub login_rate_limit_window_secs: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct ServerConfigResponse {
    pub dns_port: u16,
    pub web_port: u16,
    pub bind_address: String,
    pub pihole_compat: bool,
    pub web_tls: WebTlsConfigResponse,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct WebTlsConfigResponse {
    pub enabled: bool,
    pub tls_cert_path: String,
    pub tls_key_path: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct DnsConfigResponse {
    pub upstream_servers: Vec<String>,
    pub pools: Vec<UpstreamPoolResponse>,
    pub health_check: HealthCheckResponse,
    pub query_timeout: u64,
    pub cache_enabled: bool,
    pub cache_ttl: u32,
    /// DNSSEC enforcement mode: "off" | "permissive" | "strict". Source of truth.
    pub dnssec_mode: String,
    /// Deprecated: derived from `dnssec_mode` (`true` when validating). Kept for
    /// backward-compatibility with older API clients.
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
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    pub block_non_fqdn: bool,
    pub block_private_ptr: bool,
    pub local_domain: Option<String>,
    pub local_dns_server: Option<String>,
    pub mdns_enabled: bool,
    pub rate_limit: RateLimitConfigResponse,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct RateLimitConfigResponse {
    pub enabled: bool,
    pub queries_per_second: u32,
    pub burst_size: u32,
    pub ipv4_prefix_len: u8,
    pub ipv6_prefix_len: u8,
    pub whitelist: Vec<String>,
    pub nxdomain_per_second: u32,
    pub slip_ratio: u32,
    pub dry_run: bool,
    pub stale_entry_ttl_secs: u64,
    pub tcp_max_connections_per_ip: u32,
    pub dot_max_connections_per_ip: u32,
    pub doq_max_connections_per_ip: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct UpstreamPoolResponse {
    pub name: String,
    pub strategy: String,
    pub priority: u8,
    pub servers: Vec<String>,
    #[serde(default)]
    pub weight: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct HealthCheckResponse {
    pub enabled: bool,
    pub interval_seconds: u64,
    pub timeout_ms: u64,
    pub failure_threshold: u8,
    pub success_threshold: u8,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct BlockingConfigResponse {
    pub enabled: bool,
    pub custom_blocked: Vec<String>,
    pub whitelist: Vec<String>,
    pub block_mode: String,
    pub block_ttl: u32,
    /// Custom A target for `null_ip` blocks; empty string means the null
    /// address `0.0.0.0`.
    pub sinkhole_ipv4: String,
    /// Custom AAAA target for `null_ip` blocks; empty string means the null
    /// address `::`.
    pub sinkhole_ipv6: String,
}

/// Converts the domain `BlockResponseMode` to its snake_case API string.
pub fn block_mode_to_string(mode: ferrous_dns_domain::BlockResponseMode) -> String {
    mode.as_str().to_string()
}

/// Parses an API block-mode string; unknown values fall back to the default
/// (`NullIp`) rather than erroring, so a bad UI value can't break saving.
pub fn block_mode_from_str(value: &str) -> ferrous_dns_domain::BlockResponseMode {
    use ferrous_dns_domain::BlockResponseMode;
    match value {
        "nxdomain" => BlockResponseMode::NxDomain,
        "nodata" => BlockResponseMode::NoData,
        "refused" => BlockResponseMode::Refused,
        _ => BlockResponseMode::NullIp,
    }
}

/// Formats an optional sinkhole address as an API string (empty when unset).
pub fn sinkhole_to_string(addr: Option<impl ToString>) -> String {
    addr.map(|a| a.to_string()).unwrap_or_default()
}

/// Parses an API DNSSEC-mode string ("off" | "permissive" | "strict",
/// case-insensitive). Unknown values are rejected so a bad UI value can't
/// silently change the enforcement posture.
pub fn parse_dnssec_mode(value: &str) -> Result<ferrous_dns_domain::DnssecMode, String> {
    value.parse::<ferrous_dns_domain::DnssecMode>()
}

/// Parses an API sinkhole IPv4 string. Empty/whitespace clears it (`Ok(None)`);
/// a non-empty value that isn't a valid IPv4 address is rejected so a typo can't
/// silently revert the block target to `0.0.0.0`.
pub fn parse_sinkhole_ipv4(value: &str) -> Result<Option<Ipv4Addr>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<Ipv4Addr>()
        .map(Some)
        .map_err(|_| format!("Invalid IPv4 sinkhole address: {trimmed}"))
}

/// Parses an API sinkhole IPv6 string. Empty/whitespace clears it (`Ok(None)`);
/// a non-empty non-IPv6 value is rejected.
pub fn parse_sinkhole_ipv6(value: &str) -> Result<Option<Ipv6Addr>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    trimmed
        .parse::<Ipv6Addr>()
        .map(Some)
        .map_err(|_| format!("Invalid IPv6 sinkhole address: {trimmed}"))
}

/// Validates an API DNS64 prefix string (must be a `/96`) and returns the
/// trimmed value. A malformed or non-/96 value is rejected so a bad UI value
/// can't silently disable synthesis at the next restart.
pub fn parse_dns64_prefix(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    let cfg = ferrous_dns_domain::Dns64Config {
        enabled: true,
        prefix: trimmed.to_string(),
    };
    if cfg.parsed_prefix().is_none() {
        return Err(format!(
            "Invalid DNS64 prefix (only /96 is supported): {trimmed}"
        ));
    }
    Ok(trimmed.to_string())
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct Dns64ConfigResponse {
    pub enabled: bool,
    pub prefix: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct LoggingConfigResponse {
    pub level: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct DatabaseConfigResponse {
    pub path: String,
    pub log_queries: bool,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct UpdateConfigRequest {
    pub server: Option<ServerConfigUpdate>,
    pub dns: Option<DnsConfigUpdate>,
    pub blocking: Option<BlockingConfigUpdate>,
    pub auth: Option<AuthConfigUpdate>,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct AuthConfigUpdate {
    pub enabled: Option<bool>,
    pub session_ttl_hours: Option<u32>,
    pub remember_me_days: Option<u32>,
    pub login_rate_limit_attempts: Option<u32>,
    pub login_rate_limit_window_secs: Option<u64>,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct ServerConfigUpdate {
    pub pihole_compat: Option<bool>,
    pub web_tls: Option<WebTlsConfigUpdate>,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct WebTlsConfigUpdate {
    pub enabled: Option<bool>,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct PoolUpdate {
    pub name: String,
    pub strategy: String,
    pub priority: u8,
    pub servers: Vec<String>,
    /// Optional per-pool weight. Carried through so editing other pool fields
    /// doesn't silently drop a weight set in the config file.
    #[serde(default)]
    pub weight: Option<u32>,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct DnsConfigUpdate {
    pub pools: Option<Vec<PoolUpdate>>,
    pub upstream_servers: Option<Vec<String>>,
    pub cache_enabled: Option<bool>,
    /// DNSSEC enforcement mode: "off" | "permissive" | "strict".
    pub dnssec_mode: Option<String>,
    /// Deprecated: use `dnssec_mode`. Still accepted (`true` → permissive,
    /// `false` → off) when `dnssec_mode` is absent.
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
    pub cache_min_ttl: Option<u32>,
    pub cache_max_ttl: Option<u32>,
    pub block_non_fqdn: Option<bool>,
    pub block_private_ptr: Option<bool>,
    pub local_domain: Option<String>,
    pub local_dns_server: Option<String>,
    pub mdns_enabled: Option<bool>,
    pub rate_limit: Option<RateLimitConfigUpdate>,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct RateLimitConfigUpdate {
    pub enabled: Option<bool>,
    pub queries_per_second: Option<u32>,
    pub burst_size: Option<u32>,
    pub ipv4_prefix_len: Option<u8>,
    pub ipv6_prefix_len: Option<u8>,
    pub whitelist: Option<Vec<String>>,
    pub nxdomain_per_second: Option<u32>,
    pub slip_ratio: Option<u32>,
    pub dry_run: Option<bool>,
    pub stale_entry_ttl_secs: Option<u64>,
    pub tcp_max_connections_per_ip: Option<u32>,
    pub dot_max_connections_per_ip: Option<u32>,
    pub doq_max_connections_per_ip: Option<u32>,
}

#[derive(Deserialize, Debug, ToSchema)]
pub struct BlockingConfigUpdate {
    pub enabled: Option<bool>,
    pub custom_blocked: Option<Vec<String>>,
    pub whitelist: Option<Vec<String>>,
    pub block_mode: Option<String>,
    pub block_ttl: Option<u32>,
    /// Custom A target for `null_ip` blocks; empty string clears it.
    pub sinkhole_ipv4: Option<String>,
    /// Custom AAAA target for `null_ip` blocks; empty string clears it.
    pub sinkhole_ipv6: Option<String>,
}

fn default_block_mode() -> String {
    ferrous_dns_domain::BlockResponseMode::default()
        .as_str()
        .to_string()
}

fn default_block_ttl() -> u32 {
    ferrous_dns_domain::DEFAULT_BLOCK_TTL
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SettingsDto {
    pub never_forward_non_fqdn: bool,

    pub never_forward_reverse_lookups: bool,

    #[serde(default)]
    pub local_domain: String,

    #[serde(default)]
    pub local_dns_server: String,

    #[serde(default = "default_block_mode")]
    pub block_mode: String,

    #[serde(default = "default_block_ttl")]
    pub block_ttl: u32,

    #[serde(default)]
    pub sinkhole_ipv4: String,

    #[serde(default)]
    pub sinkhole_ipv6: String,

    #[serde(default)]
    pub dns64_enabled: bool,

    #[serde(default)]
    pub nat64_prefix: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
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
            local_domain: config.dns.local_domain.unwrap_or_default(),
            local_dns_server: config.dns.local_dns_server.unwrap_or_default(),
            block_mode: config.blocking.block_mode,
            block_ttl: config.blocking.block_ttl,
            sinkhole_ipv4: config.blocking.sinkhole_ipv4,
            sinkhole_ipv6: config.blocking.sinkhole_ipv6,
            dns64_enabled: config.dns64.enabled,
            nat64_prefix: config.dns64.prefix,
        }
    }
}
