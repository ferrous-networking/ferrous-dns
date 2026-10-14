use serde::Serialize;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/info/login response.
#[derive(Debug, Serialize, ToSchema)]
pub struct LoginInfoResponse {
    /// Whether the DNS server is up; FTL reports false only after a failure.
    pub dns: bool,
    /// HTTPS port of the web server, 0 when it serves plain HTTP.
    pub https_port: u16,
}

/// Pi-hole v6 GET /api/info/client response: the request as the server
/// received it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClientInfoResponse {
    pub remote_addr: String,
    pub http_version: String,
    pub method: String,
    pub headers: Vec<HttpHeader>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HttpHeader {
    /// Lowercase: the HTTP stack normalises header names, FTL keeps their case.
    pub name: String,
    pub value: String,
}

/// Pi-hole v6 GET /api/info/messages response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SensorsResponse {
    pub sensors: SensorsInfo,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SensorsInfo {
    pub list: Vec<SensorChip>,
    /// First temperature of the CPU sensor, null when none is found.
    pub cpu_temp: Option<f64>,
    /// FTL's default `webserver.api.temp.limit`; Ferrous has no such setting.
    pub hot_limit: f64,
    pub unit: &'static str,
}

/// One hwmon chip under `/sys/class/hwmon`.
#[derive(Debug, Serialize, ToSchema)]
pub struct SensorChip {
    /// The chip's `name` file, or its directory name without one.
    pub name: String,
    /// The `hwmonN` directory.
    pub path: String,
    /// The device the chip belongs to, null when the entry is not a link.
    pub source: Option<String>,
    pub temps: Vec<SensorTemp>,
}

/// A non-zero temperature input of a chip, in °C.
#[derive(Debug, Serialize, ToSchema)]
pub struct SensorTemp {
    pub name: Option<String>,
    pub value: f64,
    pub max: Option<f64>,
    pub crit: Option<f64>,
    /// `tempN`.
    pub sensor: String,
}

/// Pi-hole v6 GET /api/info/messages response.
#[derive(Debug, Serialize, ToSchema)]
pub struct MessagesResponse {
    pub messages: Vec<DiagnosisMessage>,
}

/// One of FTL's diagnosis messages (info.yaml). Ferrous raises none.
#[derive(Debug, Serialize, ToSchema)]
pub struct DiagnosisMessage {
    pub id: i64,
    /// Unix timestamp with fractional seconds.
    pub timestamp: f64,
    #[serde(rename = "type")]
    pub message_type: String,
    pub plain: String,
    pub html: String,
}

/// Pi-hole v6 GET /api/info/messages/count response.
#[derive(Debug, Serialize, ToSchema)]
pub struct CountResponse {
    pub count: u64,
}

/// Pi-hole v6 GET /api/info/version response.
///
/// FTL reports Pi-hole's components (core, web, FTL, docker); Ferrous is a
/// single binary, so each component carries the Ferrous version.
#[derive(Debug, Serialize, ToSchema)]
pub struct VersionResponse {
    pub version: VersionComponents,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VersionComponents {
    pub core: ComponentVersion,
    pub web: ComponentVersion,
    pub ftl: FtlComponentVersion,
    pub docker: DockerVersion,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ComponentVersion {
    pub local: LocalVersion,
    pub remote: RemoteVersion,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FtlComponentVersion {
    pub local: FtlLocalVersion,
    pub remote: RemoteVersion,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LocalVersion {
    pub branch: String,
    pub version: String,
    pub hash: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FtlLocalVersion {
    pub branch: String,
    pub version: String,
    pub hash: Option<String>,
    pub date: Option<String>,
}

/// The newest release known upstream. Ferrous does not check for updates,
/// so it repeats the local version and clients report no update.
#[derive(Debug, Serialize, ToSchema)]
pub struct RemoteVersion {
    pub version: String,
    pub hash: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DockerVersion {
    pub local: Option<String>,
    pub remote: Option<String>,
}

/// Pi-hole v6 GET /api/info/ftl response.
#[derive(Debug, Serialize, ToSchema)]
pub struct FtlInfoResponse {
    pub ftl: FtlInfo,
}

/// The resolver process; Ferrous stands in for FTL.
#[derive(Debug, Serialize, ToSchema)]
pub struct FtlInfo {
    pub database: FtlDatabaseInfo,
    /// Ferrous logs every query in full, as FTL's level 0.
    pub privacy_level: u8,
    /// Queries per second; Ferrous does not track a live rate, so 0.
    pub query_frequency: f64,
    pub clients: FtlClients,
    pub pid: u32,
    /// Milliseconds since the process started.
    pub uptime: u64,
    #[serde(rename = "%mem")]
    pub mem_percent: f64,
    /// Ferrous does not sample its CPU time, so 0.
    #[serde(rename = "%cpu")]
    pub cpu_percent: f64,
    /// Whether destructive actions (flush, restart) are served; always true.
    pub allow_destructive: bool,
    pub dnsmasq: DnsmasqMetrics,
}

/// Counts of what is configured.
#[derive(Debug, Serialize, ToSchema)]
pub struct FtlDatabaseInfo {
    /// Domains compiled from the blocklists.
    pub gravity: u64,
    /// Domains compiled from the allowlists; Ferrous does not count them, so 0.
    pub antigravity: u64,
    pub groups: u64,
    /// Block and allow lists together.
    pub lists: u64,
    pub clients: u64,
    /// Exact domains.
    pub domains: AllowedDenied,
    pub regex: AllowedDenied,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AllowedDenied {
    pub allowed: TotalEnabled,
    pub denied: TotalEnabled,
}

#[derive(Debug, Default, Serialize, ToSchema)]
pub struct TotalEnabled {
    pub total: u64,
    pub enabled: u64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct FtlClients {
    pub total: u64,
    /// Clients seen in the last 24 hours.
    pub active: u64,
}

/// dnsmasq's internal counters. Ferrous has no dnsmasq: only the cache
/// counters have an equivalent, every other one is 0.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct DnsmasqMetrics {
    pub dns_cache_inserted: u64,
    pub dns_cache_live_freed: u64,
    pub dns_queries_forwarded: u64,
    pub dns_auth_answered: u64,
    pub dns_local_answered: u64,
    pub dns_stale_answered: u64,
    pub dns_unanswered: u64,
    pub dnssec_max_crypto_use: u64,
    pub dnssec_max_sig_fail: u64,
    pub dnssec_max_work: u64,
    pub bootp: u64,
    pub pxe: u64,
    pub dhcp_ack: u64,
    pub dhcp_decline: u64,
    pub dhcp_discover: u64,
    pub dhcp_inform: u64,
    pub dhcp_nak: u64,
    pub dhcp_offer: u64,
    pub dhcp_release: u64,
    pub dhcp_request: u64,
    pub noanswer: u64,
    pub leases_allocated_4: u64,
    pub leases_pruned_4: u64,
    pub leases_allocated_6: u64,
    pub leases_pruned_6: u64,
    pub tcp_connections: u64,
    pub dhcp_leasequery: u64,
    pub dhcp_lease_unassigned: u64,
    /// Sic: FTL spells it this way.
    pub dhcp_lease_actve: u64,
    pub dhcp_lease_unknown: u64,
}

/// Pi-hole v6 GET /api/info/metrics response.
#[derive(Debug, Serialize, ToSchema)]
pub struct MetricsResponse {
    pub metrics: Metrics,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Metrics {
    pub dns: DnsMetrics,
    pub dhcp: DhcpMetrics,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DnsMetrics {
    pub cache: CacheMetrics,
    pub replies: ReplyMetrics,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CacheMetrics {
    /// Configured cache capacity, 0 with the cache off.
    pub size: u64,
    /// Entries inserted since start.
    pub inserted: u64,
    /// Live entries removed before their expiry.
    pub evicted: u64,
    /// Expired entries removed when a lookup found them.
    pub expired: u64,
    /// Not counted by Ferrous, so 0.
    pub immortal: u64,
    /// Per-type counts; Ferrous does not keep them, so empty.
    pub content: Vec<CacheContent>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CacheContent {
    #[serde(rename = "type")]
    pub rr_type: u16,
    pub name: String,
    pub count: CacheContentCount,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CacheContentCount {
    pub valid: u64,
    pub stale: u64,
}

/// dnsmasq's reply counters; Ferrous has no dnsmasq, so all are 0.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct ReplyMetrics {
    pub local: u64,
    pub forwarded: u64,
    pub optimized: u64,
    pub unanswered: u64,
    pub auth: u64,
    pub sum: u64,
}

/// dnsmasq's DHCP counters; Ferrous serves no DHCP, so all are 0.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct DhcpMetrics {
    pub ack: u64,
    pub decline: u64,
    pub discover: u64,
    pub inform: u64,
    pub nak: u64,
    pub offer: u64,
    pub release: u64,
    pub request: u64,
    pub noanswer: u64,
    pub bootp: u64,
    pub pxe: u64,
    pub leases: DhcpLeaseMetrics,
}

#[derive(Debug, Default, Serialize, ToSchema)]
pub struct DhcpLeaseMetrics {
    pub allocated_4: u64,
    pub pruned_4: u64,
    pub allocated_6: u64,
    pub pruned_6: u64,
}

/// Pi-hole v6 GET /api/info/system response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SystemInfoResponse {
    pub system: SystemInfo,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SystemInfo {
    /// Seconds since the host booted.
    pub uptime: u64,
    pub memory: SystemMemory,
    /// Processes and threads on the host.
    pub procs: u64,
    pub cpu: SystemCpu,
    pub ftl: ProcessUsage,
}

/// Host memory, in kilobytes.
#[derive(Debug, Serialize, ToSchema)]
pub struct SystemMemory {
    pub ram: RamInfo,
    pub swap: SwapInfo,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RamInfo {
    pub total: u64,
    pub free: u64,
    /// Not free and not reclaimable as cache or buffers.
    pub used: u64,
    pub available: u64,
    #[serde(rename = "%used")]
    pub used_percent: f64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SwapInfo {
    pub total: u64,
    pub free: u64,
    pub used: u64,
    #[serde(rename = "%used")]
    pub used_percent: f64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SystemCpu {
    /// Configured processors.
    pub nprocs: u64,
    /// Ferrous does not sample host CPU time, so 0.
    #[serde(rename = "%cpu")]
    pub cpu_percent: f64,
    pub load: SystemLoad,
}

/// 1, 5 and 15 minute load averages.
#[derive(Debug, Serialize, ToSchema)]
pub struct SystemLoad {
    pub raw: [f64; 3],
    /// `raw` relative to `nprocs`.
    pub percent: [f64; 3],
}

/// The resolver process's share of the host.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProcessUsage {
    #[serde(rename = "%mem")]
    pub mem_percent: f64,
    /// Ferrous does not sample its CPU time, so 0.
    #[serde(rename = "%cpu")]
    pub cpu_percent: f64,
}

/// Pi-hole v6 GET /api/info/host response.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostInfoResponse {
    pub host: HostInfo,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HostInfo {
    pub uname: HostUname,
    /// Device-tree model, null where there is none (most x86 hosts).
    pub model: Option<String>,
    pub dmi: HostDmi,
}

/// The kernel's `uname(2)`.
#[derive(Debug, Default, Serialize, ToSchema)]
pub struct HostUname {
    pub domainname: String,
    pub machine: String,
    pub nodename: String,
    pub release: String,
    pub sysname: String,
    pub version: String,
}

/// Firmware identifiers; each null where the host does not expose it.
#[derive(Debug, Serialize, ToSchema)]
pub struct HostDmi {
    pub bios: DmiVendor,
    pub board: DmiBoard,
    pub product: DmiProduct,
    pub sys: DmiVendor,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DmiVendor {
    pub vendor: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DmiBoard {
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DmiProduct {
    pub name: Option<String>,
    pub family: Option<String>,
    pub version: Option<String>,
}

/// Pi-hole v6 GET /api/info/database response: the database file and the
/// query log it holds.
#[derive(Debug, Serialize, ToSchema)]
pub struct DatabaseInfoResponse {
    /// File size in bytes.
    pub size: u64,
    /// `Regular file`, or `Unknown` when it is something else or unreadable.
    #[serde(rename = "type")]
    pub file_type: String,
    /// Permissions as `ls` prints them, such as `rw-r--r--`.
    pub mode: String,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub owner: DatabaseOwner,
    /// Queries of the last 24 hours.
    pub queries: u64,
    pub earliest_timestamp: f64,
    /// Every stored query.
    pub queries_disk: u64,
    pub earliest_timestamp_disk: f64,
    pub sqlite_version: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DatabaseOwner {
    pub user: DatabaseOwnerUser,
    pub group: DatabaseOwnerGroup,
}

/// `name` and `info` are null when the uid is not in `/etc/passwd`.
#[derive(Debug, Serialize, ToSchema)]
pub struct DatabaseOwnerUser {
    pub uid: u32,
    pub name: Option<String>,
    pub info: Option<String>,
}

/// `name` is null when the gid is not in `/etc/group`.
#[derive(Debug, Serialize, ToSchema)]
pub struct DatabaseOwnerGroup {
    pub gid: u32,
    pub name: Option<String>,
}
