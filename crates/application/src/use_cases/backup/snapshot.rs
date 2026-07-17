use serde::{Deserialize, Serialize};

/// Full configuration snapshot exported by the backup use case.
///
/// The format version is "1". Future breaking changes bump this string
/// so the import use case can reject incompatible files early.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupSnapshot {
    pub version: String,
    pub ferrous_version: String,
    pub exported_at: String,
    pub config: SnapshotConfig,
    pub data: SnapshotData,
}

/// Configuration section of the snapshot.
///
/// Mirrors the fields the user can meaningfully restore, without any
/// secrets (password hashes, TLS private key contents, API token hashes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    pub server: SnapshotServerConfig,
    pub dns: SnapshotDnsConfig,
    pub blocking: SnapshotBlockingConfig,
    // Absent from pre-0.9.2 backups; serde default keeps older files importable
    // (DNS64 disabled, well-known prefix).
    #[serde(default)]
    pub dns64: SnapshotDns64Config,
    pub logging: SnapshotLoggingConfig,
    pub auth: SnapshotAuthConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotServerConfig {
    pub dns_port: u16,
    pub web_port: u16,
    pub bind_address: String,
    pub pihole_compat: bool,
    /// TLS cert/key paths are exported (paths ok, content not).
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub tls_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotDnsConfig {
    pub upstream_servers: Vec<String>,
    pub cache_enabled: bool,
    /// DNSSEC enforcement mode ("off" | "permissive" | "strict"). New field.
    #[serde(default)]
    pub dnssec_mode: Option<String>,
    /// Deprecated: older snapshots stored a boolean. Read for back-compat.
    #[serde(default)]
    pub dnssec_enabled: Option<bool>,
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
    #[serde(default)]
    pub mdns_enabled: bool,
    pub local_domain: Option<String>,
    pub local_dns_server: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotBlockingConfig {
    pub enabled: bool,
    pub custom_blocked: Vec<String>,
    pub whitelist: Vec<String>,
    // The following are absent from pre-0.9 backups; serde defaults keep those
    // older files importable (block_mode → null_ip, block_ttl → 60, sinkhole → none).
    #[serde(default)]
    pub block_mode: ferrous_dns_domain::BlockResponseMode,
    #[serde(default = "default_block_ttl")]
    pub block_ttl: u32,
    #[serde(default)]
    pub sinkhole_ipv4: Option<std::net::Ipv4Addr>,
    #[serde(default)]
    pub sinkhole_ipv6: Option<std::net::Ipv6Addr>,
}

fn default_block_ttl() -> u32 {
    ferrous_dns_domain::DEFAULT_BLOCK_TTL
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SnapshotDns64Config {
    #[serde(default)]
    pub enabled: bool,
    /// `None` in older/default backups; import falls back to the well-known
    /// prefix.
    #[serde(default)]
    pub prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotLoggingConfig {
    pub level: String,
}

/// Auth config without any secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotAuthConfig {
    pub enabled: bool,
    pub session_ttl_hours: u32,
    pub remember_me_days: u32,
    pub login_rate_limit_attempts: u32,
    pub login_rate_limit_window_secs: u64,
    #[serde(default)]
    pub webauthn_rp_id: String,
    #[serde(default)]
    pub webauthn_rp_origin: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotData {
    pub groups: Vec<GroupSnapshot>,
    pub blocklist_sources: Vec<BlocklistSourceSnapshot>,
    pub local_records: Vec<LocalRecordSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupSnapshot {
    pub name: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlocklistSourceSnapshot {
    pub name: String,
    pub url: Option<String>,
    pub group_ids: Vec<i64>,
    pub comment: Option<String>,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalRecordSnapshot {
    pub hostname: String,
    pub domain: Option<String>,
    pub ip: String,
    pub record_type: String,
    pub ttl: Option<u32>,
}

/// Summary returned to callers after a successful import.
#[derive(Debug, Clone)]
pub struct ImportSummary {
    pub config_updated: bool,
    pub groups_imported: usize,
    pub groups_skipped: usize,
    pub blocklist_sources_imported: usize,
    pub blocklist_sources_skipped: usize,
    pub local_records_imported: usize,
    pub local_records_skipped: usize,
    pub errors: Vec<String>,
}
