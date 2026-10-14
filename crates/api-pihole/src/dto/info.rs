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

/// dnsmasq's internal counters. Ferrous has no dnsmasq, so all are 0.
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
