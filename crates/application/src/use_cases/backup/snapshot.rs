use ferrous_dns_domain::config::{
    CacheEvictionStrategy, DgaDetectionConfig, NxdomainHijackConfig, RateLimitConfig,
    ResponseIpFilterConfig, TunnelingDetectionConfig,
};
use ferrous_dns_domain::UpstreamPool;
use serde::{Deserialize, Deserializer, Serialize};

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
/// Backups from older releases also carry keys nothing read
/// (`cache_adaptive_thresholds`, `custom_blocked`, `whitelist`, pool `weight`),
/// which serde ignores.
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
    /// `Some(None)` when the exporting server had none, so the web server shares
    /// `bind_address`. `None` when the backup predates the key, which keeps
    /// this server's own value.
    #[serde(default, deserialize_with = "present")]
    pub web_bind_address: Option<Option<String>>,
    pub pihole_compat: bool,
    /// Exported, never restored: only this server's config file sets where
    /// `/tls/upload` writes. Older releases still need the keys to import a backup.
    pub tls_cert_path: String,
    pub tls_key_path: String,
    pub tls_enabled: bool,
}

/// Tells a key that is present, `null` included, from a missing one, which
/// `#[serde(default)]` leaves at `None`.
fn present<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(deserializer).map(Some)
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
    pub cache_eviction_strategy: CacheEvictionStrategy,
    pub cache_max_entries: usize,
    pub cache_min_hit_rate: f64,
    pub cache_min_frequency: u64,
    pub cache_min_lfuk_score: f64,
    pub cache_compaction_interval: u64,
    pub cache_refresh_threshold: f64,
    pub cache_optimistic_refresh: bool,
    pub cache_access_window_secs: u64,
    pub cache_min_ttl: u32,
    pub cache_max_ttl: u32,
    pub block_non_fqdn: bool,
    pub block_private_ptr: bool,
    #[serde(default)]
    pub mdns_enabled: bool,
    pub local_domain: Option<String>,
    pub local_dns_server: Option<String>,
    // The three below are absent from older backups; `None` keeps the
    // target's own values. Pool `groups` hold the exporting server's group
    // ids, which the import translates.
    #[serde(default)]
    pub pools: Option<Vec<UpstreamPool>>,
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    #[serde(default)]
    pub malware: Option<SnapshotMalwareConfig>,
}

/// The Malware Detection settings: the master switch and the five detectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMalwareConfig {
    pub enabled: bool,
    pub rebinding_protection_enabled: bool,
    pub tunneling_detection: TunnelingDetectionConfig,
    pub dga_detection: DgaDetectionConfig,
    pub nxdomain_hijack: NxdomainHijackConfig,
    pub response_ip_filter: ResponseIpFilterConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotBlockingConfig {
    pub enabled: bool,
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
    /// The group's id on the exporting server, which pools and blocklist
    /// sources refer to. Absent from older backups.
    #[serde(default)]
    pub id: Option<i64>,
    pub name: String,
    pub comment: Option<String>,
    #[serde(default)]
    pub is_default: bool,
    /// Absent from older backups: a group they create starts enabled, and
    /// one that exists here keeps its own switch.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Absent from older backups: a group they create starts with the
    /// detectors on, and one that exists here keeps its own switch.
    #[serde(default)]
    pub malware_detection_enabled: Option<bool>,
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
    /// The restored config differs from the one running, which only a
    /// restart applies.
    pub restart_required: bool,
    pub groups_imported: usize,
    pub groups_skipped: usize,
    pub blocklist_sources_imported: usize,
    pub blocklist_sources_skipped: usize,
    pub local_records_imported: usize,
    pub local_records_skipped: usize,
    pub errors: Vec<String>,
    /// What was restored differently from the backup, and why.
    pub warnings: Vec<String>,
}
