//! Strict mirrors of Pi-hole FTL's v6 API response schemas.
//!
//! Each struct is transcribed from FTL's OpenAPI spec in
//! `src/api/docs/content/specs/` at FTL commit
//! `0bf029baf174f65852a0e598bf4efa436e5cda9c`. Where the YAML and the C code
//! disagree on what is actually emitted, the C code wins and a one-line comment
//! says so. Every struct denies unknown fields, so [`assert_ftl_shape`] catches
//! extra, missing and wrongly-typed fields in a compat response. `took` is
//! optional everywhere because Ferrous intentionally does not send it.

use std::any::type_name;
use std::collections::HashMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};
use serde_json::Value;

/// Deserializes `body` into the FTL mirror `T`, panicking with the serde error
/// and the pretty-printed body when the shape does not match.
pub fn assert_ftl_shape<T: DeserializeOwned>(body: &Value) -> T {
    match T::deserialize(body) {
        Ok(value) => value,
        Err(err) => panic!(
            "response does not match FTL schema `{}`: {err}\nbody:\n{}",
            type_name::<T>(),
            serde_json::to_string_pretty(body).unwrap_or_else(|_| body.to_string()),
        ),
    }
}

/// Requires the key to be present while allowing `null`, unlike a plain
/// `Option` which serde also fills in when the key is missing.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

// ---------------------------------------------------------------------------
// Shared enums
// ---------------------------------------------------------------------------

/// Blocking status string — dns.yaml:73.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum BlockingStatus {
    #[serde(rename = "enabled")]
    Enabled,
    #[serde(rename = "disabled")]
    Disabled,
    #[serde(rename = "failed")]
    Failed,
    #[serde(rename = "unknown")]
    Unknown,
}

/// `status` of a success reply — common.yaml:11.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum SuccessStatus {
    #[serde(rename = "success")]
    Success,
}

/// Domain type — domains.yaml:366.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum DomainType {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "deny")]
    Deny,
}

/// Domain kind — domains.yaml:376.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum DomainKind {
    #[serde(rename = "exact")]
    Exact,
    #[serde(rename = "regex")]
    Regex,
}

/// List type — lists.yaml:333.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum ListType {
    #[serde(rename = "allow")]
    Allow,
    #[serde(rename = "block")]
    Block,
}

/// Query status — values from `get_query_status_str()` (datastructure.c), referenced by queries.yaml:189.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum QueryStatus {
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "GRAVITY")]
    Gravity,
    #[serde(rename = "FORWARDED")]
    Forwarded,
    #[serde(rename = "CACHE")]
    Cache,
    #[serde(rename = "REGEX")]
    Regex,
    #[serde(rename = "DENYLIST")]
    Denylist,
    #[serde(rename = "EXTERNAL_BLOCKED_IP")]
    ExternalBlockedIp,
    #[serde(rename = "EXTERNAL_BLOCKED_NULL")]
    ExternalBlockedNull,
    #[serde(rename = "EXTERNAL_BLOCKED_NXRA")]
    ExternalBlockedNxra,
    #[serde(rename = "GRAVITY_CNAME")]
    GravityCname,
    #[serde(rename = "REGEX_CNAME")]
    RegexCname,
    #[serde(rename = "DENYLIST_CNAME")]
    DenylistCname,
    #[serde(rename = "RETRIED")]
    Retried,
    #[serde(rename = "RETRIED_DNSSEC")]
    RetriedDnssec,
    #[serde(rename = "IN_PROGRESS")]
    InProgress,
    #[serde(rename = "DBBUSY")]
    DbBusy,
    #[serde(rename = "SPECIAL_DOMAIN")]
    SpecialDomain,
    #[serde(rename = "CACHE_STALE")]
    CacheStale,
    #[serde(rename = "EXTERNAL_BLOCKED_EDE15")]
    ExternalBlockedEde15,
}

/// Reply type — values from `get_query_reply_str()` (datastructure.c), referenced by queries.yaml:210.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum ReplyType {
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "NODATA")]
    NoData,
    #[serde(rename = "NXDOMAIN")]
    NxDomain,
    #[serde(rename = "CNAME")]
    Cname,
    #[serde(rename = "IP")]
    Ip,
    #[serde(rename = "DOMAIN")]
    Domain,
    #[serde(rename = "RRNAME")]
    RrName,
    #[serde(rename = "SERVFAIL")]
    ServFail,
    #[serde(rename = "REFUSED")]
    Refused,
    #[serde(rename = "NOTIMP")]
    NotImp,
    #[serde(rename = "OTHER")]
    Other,
    #[serde(rename = "DNSSEC")]
    Dnssec,
    #[serde(rename = "NONE")]
    NoReply,
    #[serde(rename = "BLOB")]
    Blob,
}

/// DNSSEC status — values from `get_query_dnssec_str()` (datastructure.c), referenced by queries.yaml:203.
#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum DnssecStatus {
    #[serde(rename = "UNKNOWN")]
    Unknown,
    #[serde(rename = "SECURE")]
    Secure,
    #[serde(rename = "INSECURE")]
    Insecure,
    #[serde(rename = "BOGUS")]
    Bogus,
    #[serde(rename = "ABANDONED")]
    Abandoned,
    #[serde(rename = "TRUNCATED")]
    Truncated,
}

// ---------------------------------------------------------------------------
// Errors and simple replies
// ---------------------------------------------------------------------------

/// Error envelope for every 4xx/5xx reply — common.yaml:19.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorReply {
    pub error: ErrorBody,
    pub took: Option<f64>,
}

/// `error` object of the error envelope — common.yaml:23.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub key: String,
    pub message: String,
    #[serde(deserialize_with = "required_nullable")]
    pub hint: Option<String>,
}

/// `POST /action/restartdns` and `POST /action/flush/logs` — common.yaml:11 via action.yaml:70,95.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSuccess {
    pub status: SuccessStatus,
    pub took: Option<f64>,
}

// ---------------------------------------------------------------------------
// /auth
// ---------------------------------------------------------------------------

/// `GET/POST /auth` session reply — auth.yaml:277.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSession {
    pub session: Session,
    pub took: Option<f64>,
}

/// `session` object — auth.yaml:282.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub valid: bool,
    pub totp: bool,
    // C (auth.c get_session_object) always adds `sid`, as null without a session.
    #[serde(deserialize_with = "required_nullable")]
    pub sid: Option<String>,
    // C (auth.c get_session_object) omits `csrf` unless a session is valid.
    pub csrf: Option<String>,
    pub validity: i64,
    pub message: Option<String>,
}

/// `GET /auth/sessions` — auth.c:325-361 (get_all_sessions).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthSessions {
    pub sessions: Vec<SessionEntry>,
    pub took: Option<f64>,
}

/// `sessions[]` — auth.c:334-355.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionEntry {
    pub id: i64,
    pub current_session: bool,
    pub valid: bool,
    pub tls: SessionTls,
    pub login_at: i64,
    pub last_active: i64,
    pub valid_until: i64,
    pub remote_addr: String,
    #[serde(deserialize_with = "required_nullable")]
    pub user_agent: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub x_forwarded_for: Option<String>,
    pub app: bool,
    pub cli: bool,
}

/// `sessions[].tls` — auth.c:338-341.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionTls {
    pub login: bool,
    pub mixed: bool,
}

// ---------------------------------------------------------------------------
// /info
// ---------------------------------------------------------------------------

/// `GET /info/login` — info.yaml:1305.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoLogin {
    pub https_port: u64,
    pub dns: bool,
    pub took: Option<f64>,
}

/// `GET /info/version` — info.yaml:1019.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoVersion {
    pub version: VersionData,
    pub took: Option<f64>,
}

/// `version` object — info.yaml:1022.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionData {
    pub core: ComponentVersion,
    pub web: ComponentVersion,
    pub ftl: FtlComponentVersion,
    pub docker: DockerVersion,
}

/// `version.core` / `version.web` — info.yaml:1025.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentVersion {
    pub local: LocalVersion,
    pub remote: RemoteVersion,
}

/// `version.ftl` — info.yaml:1093.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FtlComponentVersion {
    pub local: FtlLocalVersion,
    pub remote: RemoteVersion,
}

/// `version.{core,web}.local` — info.yaml:1028.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVersion {
    pub branch: Option<String>,
    pub version: Option<String>,
    pub hash: Option<String>,
}

/// `version.ftl.local` — info.yaml:1096.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FtlLocalVersion {
    pub branch: Option<String>,
    pub version: Option<String>,
    pub hash: Option<String>,
    pub date: Option<String>,
}

/// `version.*.remote` — info.yaml:1046.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteVersion {
    pub version: Option<String>,
    pub hash: Option<String>,
}

/// `version.docker` — info.yaml:1132.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DockerVersion {
    pub local: Option<String>,
    pub remote: Option<String>,
}

/// `GET /info/ftl` — info.yaml:700.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoFtl {
    pub ftl: FtlData,
    pub took: Option<f64>,
}

/// `ftl` object — info.yaml:703.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FtlData {
    pub database: FtlDatabase,
    pub privacy_level: i64,
    pub query_frequency: f64,
    pub clients: FtlClients,
    pub pid: i64,
    pub uptime: f64,
    #[serde(rename = "%mem")]
    pub mem_percent: f64,
    #[serde(rename = "%cpu")]
    pub cpu_percent: f64,
    pub allow_destructive: bool,
    pub dnsmasq: DnsmasqMetrics,
}

/// `ftl.database` — info.yaml:706.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FtlDatabase {
    pub gravity: u64,
    pub antigravity: u64,
    pub groups: u64,
    pub lists: u64,
    pub clients: u64,
    pub domains: AllowedDenied,
    pub regex: AllowedDenied,
}

/// `ftl.database.{domains,regex}` — info.yaml:729.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowedDenied {
    pub allowed: TotalEnabled,
    pub denied: TotalEnabled,
}

/// `{total, enabled}` counter pair — info.yaml:733.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TotalEnabled {
    pub total: u64,
    pub enabled: u64,
}

/// `ftl.clients` — info.yaml:787.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FtlClients {
    pub total: u64,
    pub active: u64,
}

/// `ftl.dnsmasq` — info.yaml:818.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsmasqMetrics {
    pub dns_cache_inserted: u64,
    pub dns_cache_live_freed: u64,
    pub dns_queries_forwarded: u64,
    pub dns_auth_answered: u64,
    pub dns_local_answered: u64,
    pub dns_stale_answered: u64,
    pub dns_unanswered: u64,
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
    pub dhcp_lease_actve: u64,
    pub dhcp_lease_unknown: u64,
    pub dnssec_max_crypto_use: u64,
    pub dnssec_max_sig_fail: u64,
    pub dnssec_max_work: u64,
}

/// `GET /info/system` — info.yaml:394.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoSystem {
    pub system: SystemData,
    pub took: Option<f64>,
}

/// `system` object (also embedded in `/padd`) — info.yaml:397.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemData {
    pub uptime: u64,
    pub memory: SystemMemory,
    pub procs: u64,
    pub cpu: SystemCpu,
    pub ftl: SystemFtl,
}

/// `system.memory` (kilobytes) — info.yaml:404.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemMemory {
    pub ram: SystemRam,
    pub swap: SystemSwap,
}

/// `system.memory.ram` — info.yaml:408.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemRam {
    pub total: u64,
    pub free: u64,
    pub used: u64,
    pub available: u64,
    #[serde(rename = "%used")]
    pub used_percent: f64,
}

/// `system.memory.swap` — info.yaml:432.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemSwap {
    pub total: u64,
    pub used: u64,
    pub free: u64,
    #[serde(rename = "%used")]
    pub used_percent: f64,
}

/// `system.cpu` — info.yaml:456.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemCpu {
    pub nprocs: u64,
    #[serde(rename = "%cpu")]
    pub cpu_percent: f64,
    pub load: SystemLoad,
}

/// `system.cpu.load` — info.yaml:468.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemLoad {
    pub raw: Vec<f64>,
    pub percent: Vec<f64>,
}

/// `system.ftl` — info.yaml:484.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemFtl {
    #[serde(rename = "%mem")]
    pub mem_percent: f64,
    #[serde(rename = "%cpu")]
    pub cpu_percent: f64,
}

/// `GET /info/host` — info.yaml:613.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoHost {
    pub host: HostData,
    pub took: Option<f64>,
}

/// `host` object — info.yaml:616.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostData {
    pub uname: HostUname,
    pub model: Option<String>,
    pub dmi: HostDmi,
}

/// `host.uname` — info.yaml:619.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostUname {
    pub domainname: String,
    pub machine: String,
    pub nodename: String,
    pub release: String,
    pub sysname: String,
    pub version: String,
}

/// `host.dmi` — info.yaml:645.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDmi {
    pub bios: DmiVendor,
    pub board: DmiBoard,
    pub product: DmiProduct,
    pub sys: DmiVendor,
}

/// `host.dmi.bios` / `host.dmi.sys` — info.yaml:648.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DmiVendor {
    pub vendor: Option<String>,
}

/// `host.dmi.board` — info.yaml:656.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DmiBoard {
    pub name: Option<String>,
    pub vendor: Option<String>,
    pub version: Option<String>,
}

/// `host.dmi.product` — info.yaml:674.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DmiProduct {
    pub name: Option<String>,
    pub version: Option<String>,
    pub family: Option<String>,
}

/// `GET /info/database` — info.yaml:943.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoDatabase {
    pub size: u64,
    #[serde(rename = "type")]
    pub file_type: String,
    pub mode: String,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
    pub owner: DatabaseOwner,
    pub queries: u64,
    pub earliest_timestamp: f64,
    pub queries_disk: u64,
    pub earliest_timestamp_disk: f64,
    pub sqlite_version: String,
    pub took: Option<f64>,
}

/// `owner` — info.yaml:970.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseOwner {
    pub user: DatabaseOwnerUser,
    pub group: DatabaseOwnerGroup,
}

/// `owner.user` — info.yaml:973.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseOwnerUser {
    pub uid: i64,
    // C (info.c api_info_database) emits null for `name`/`info` when getpwuid fails; YAML says string.
    pub name: Option<String>,
    pub info: Option<String>,
}

/// `owner.group` — info.yaml:988.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseOwnerGroup {
    pub gid: i64,
    // C (info.c api_info_database) emits null for `name` when getgrgid fails; YAML says string.
    pub name: Option<String>,
}

/// `GET /info/client` — info.c:63-88 (api_info_client).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoClient {
    pub remote_addr: String,
    pub http_version: String,
    pub method: String,
    pub headers: Vec<HttpHeader>,
    pub took: Option<f64>,
}

/// `headers[]` — info.c:76-83.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpHeader {
    pub name: String,
    pub value: String,
}

/// `GET /info/sensors` — info.c:770-780 (api_info_sensors).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoSensors {
    pub sensors: Sensors,
    pub took: Option<f64>,
}

/// `sensors` — info.c:698-768 (get_sensors_obj with the list).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sensors {
    pub list: Vec<SensorChip>,
    #[serde(deserialize_with = "required_nullable")]
    pub cpu_temp: Option<f64>,
    pub hot_limit: f64,
    pub unit: String,
}

/// `list[]` — info.c:441-452 (get_hwmon_sensors).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorChip {
    pub name: String,
    pub path: String,
    // C: JSON_COPY_STR_TO_OBJECT turns a missing symlink target into null.
    #[serde(deserialize_with = "required_nullable")]
    pub source: Option<String>,
    pub temps: Vec<SensorTemp>,
}

/// `temps[]` — info.c:298-365 (read_hwmon_sensors).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SensorTemp {
    #[serde(deserialize_with = "required_nullable")]
    pub name: Option<String>,
    pub value: f64,
    #[serde(deserialize_with = "required_nullable")]
    pub max: Option<f64>,
    #[serde(deserialize_with = "required_nullable")]
    pub crit: Option<f64>,
    pub sensor: String,
}

/// `GET /info/messages` — info.yaml:1145.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoMetrics {
    pub metrics: Metrics,
    pub took: Option<f64>,
}

/// `metrics` — info.c:1075-1150 (api_info_metrics).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    pub dns: MetricsDns,
    pub dhcp: MetricsDhcp,
}

/// `metrics.dns` — info.c:1139-1141.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsDns {
    pub cache: MetricsCache,
    pub replies: MetricsReplies,
}

/// `metrics.dns.cache` — info.c:1079-1104.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsCache {
    pub size: u64,
    pub inserted: u64,
    pub evicted: u64,
    pub expired: u64,
    pub immortal: u64,
    pub content: Vec<MetricsCacheContent>,
}

/// `metrics.dns.cache.content[]` — info.c:1095-1102.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsCacheContent {
    #[serde(rename = "type")]
    pub rr_type: u64,
    pub name: String,
    pub count: MetricsCacheCount,
}

/// `content[].count` — info.c:1098-1101.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsCacheCount {
    pub valid: u64,
    pub stale: u64,
}

/// `metrics.dns.replies` — info.c:1106-1117.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsReplies {
    pub local: u64,
    pub forwarded: u64,
    pub optimized: u64,
    pub unanswered: u64,
    pub auth: u64,
    pub sum: u64,
}

/// `metrics.dhcp` — info.c:1119-1137.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsDhcp {
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
    pub leases: MetricsDhcpLeases,
}

/// `metrics.dhcp.leases` — info.c:1132-1137.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsDhcpLeases {
    pub allocated_4: u64,
    pub pruned_4: u64,
    pub allocated_6: u64,
    pub pruned_6: u64,
}

/// `GET /info/messages` — info.yaml:1145.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoMessages {
    pub messages: Vec<InfoMessage>,
    pub took: Option<f64>,
}

/// `messages[]` — info.yaml:1150.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InfoMessage {
    pub id: i64,
    pub timestamp: f64,
    #[serde(rename = "type")]
    pub message_type: String,
    pub plain: String,
    pub html: String,
}

/// `GET /info/messages/count` — info.yaml:1298.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Count {
    pub count: i64,
    pub took: Option<f64>,
}

// ---------------------------------------------------------------------------
// /dhcp
// ---------------------------------------------------------------------------

/// `GET /dhcp/leases` — dhcp.yaml:70.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpLeases {
    pub leases: Vec<DhcpLease>,
    pub took: Option<f64>,
}

/// `leases[]` — dhcp.yaml:77.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DhcpLease {
    pub expires: i64,
    pub name: String,
    pub hwaddr: String,
    pub ip: String,
    pub clientid: String,
}

/// An empty JSON object — FTL's body for a 404 without an error envelope
/// (`DELETE /info/messages/{id}` naming no message).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {
    pub took: Option<f64>,
}

// ---------------------------------------------------------------------------
// /dns
// ---------------------------------------------------------------------------

/// `GET/POST /dns/blocking` — dns.yaml:73 + dns.yaml:93.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsBlocking {
    pub blocking: BlockingStatus,
    pub timer: Option<f64>,
    pub took: Option<f64>,
}

// ---------------------------------------------------------------------------
// /stats
// ---------------------------------------------------------------------------

/// `GET /stats/summary` — stats.yaml:311.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsSummary {
    pub queries: SummaryQueries,
    pub clients: SummaryClients,
    pub gravity: SummaryGravity,
    pub took: Option<f64>,
}

/// `queries` object of the summary — stats.yaml:314.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryQueries {
    pub total: u64,
    pub blocked: u64,
    pub percent_blocked: f64,
    pub unique_domains: u64,
    pub forwarded: u64,
    pub cached: u64,
    pub frequency: f64,
    pub types: QueryTypeCounts,
    pub status: QueryStatusCounts,
    pub replies: ReplyTypeCounts,
}

/// Per-query-type counters (summary `types`, `/stats/query_types`) — stats.yaml:345.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryTypeCounts {
    #[serde(rename = "A")]
    pub a: u64,
    #[serde(rename = "AAAA")]
    pub aaaa: u64,
    #[serde(rename = "ANY")]
    pub any: u64,
    #[serde(rename = "SRV")]
    pub srv: u64,
    #[serde(rename = "SOA")]
    pub soa: u64,
    #[serde(rename = "PTR")]
    pub ptr: u64,
    #[serde(rename = "TXT")]
    pub txt: u64,
    #[serde(rename = "NAPTR")]
    pub naptr: u64,
    #[serde(rename = "MX")]
    pub mx: u64,
    #[serde(rename = "DS")]
    pub ds: u64,
    #[serde(rename = "RRSIG")]
    pub rrsig: u64,
    #[serde(rename = "DNSKEY")]
    pub dnskey: u64,
    #[serde(rename = "NS")]
    pub ns: u64,
    #[serde(rename = "SVCB")]
    pub svcb: u64,
    #[serde(rename = "HTTPS")]
    pub https: u64,
    #[serde(rename = "OTHER")]
    pub other: u64,
}

/// Per-status counters (summary `status`) — stats.yaml:413.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryStatusCounts {
    #[serde(rename = "UNKNOWN")]
    pub unknown: u64,
    #[serde(rename = "GRAVITY")]
    pub gravity: u64,
    #[serde(rename = "FORWARDED")]
    pub forwarded: u64,
    #[serde(rename = "CACHE")]
    pub cache: u64,
    #[serde(rename = "REGEX")]
    pub regex: u64,
    #[serde(rename = "DENYLIST")]
    pub denylist: u64,
    #[serde(rename = "EXTERNAL_BLOCKED_IP")]
    pub external_blocked_ip: u64,
    #[serde(rename = "EXTERNAL_BLOCKED_NULL")]
    pub external_blocked_null: u64,
    #[serde(rename = "EXTERNAL_BLOCKED_NXRA")]
    pub external_blocked_nxra: u64,
    #[serde(rename = "GRAVITY_CNAME")]
    pub gravity_cname: u64,
    #[serde(rename = "REGEX_CNAME")]
    pub regex_cname: u64,
    #[serde(rename = "DENYLIST_CNAME")]
    pub denylist_cname: u64,
    #[serde(rename = "RETRIED")]
    pub retried: u64,
    #[serde(rename = "RETRIED_DNSSEC")]
    pub retried_dnssec: u64,
    #[serde(rename = "IN_PROGRESS")]
    pub in_progress: u64,
    #[serde(rename = "DBBUSY")]
    pub dbbusy: u64,
    #[serde(rename = "SPECIAL_DOMAIN")]
    pub special_domain: u64,
    #[serde(rename = "CACHE_STALE")]
    pub cache_stale: u64,
    #[serde(rename = "EXTERNAL_BLOCKED_EDE15")]
    pub external_blocked_ede15: u64,
}

/// Per-reply-type counters (summary `replies`) — stats.yaml:493.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplyTypeCounts {
    #[serde(rename = "UNKNOWN")]
    pub unknown: u64,
    #[serde(rename = "NODATA")]
    pub nodata: u64,
    #[serde(rename = "NXDOMAIN")]
    pub nxdomain: u64,
    #[serde(rename = "CNAME")]
    pub cname: u64,
    #[serde(rename = "IP")]
    pub ip: u64,
    #[serde(rename = "DOMAIN")]
    pub domain: u64,
    #[serde(rename = "RRNAME")]
    pub rrname: u64,
    #[serde(rename = "SERVFAIL")]
    pub servfail: u64,
    #[serde(rename = "REFUSED")]
    pub refused: u64,
    #[serde(rename = "NOTIMP")]
    pub notimp: u64,
    #[serde(rename = "OTHER")]
    pub other: u64,
    #[serde(rename = "DNSSEC")]
    pub dnssec: u64,
    #[serde(rename = "NONE")]
    pub none: u64,
    #[serde(rename = "BLOB")]
    pub blob: u64,
}

/// `clients` object of the summary — stats.yaml:553.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryClients {
    pub active: u64,
    pub total: u64,
}

/// `gravity` object of the summary — stats.yaml:564.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SummaryGravity {
    pub domains_being_blocked: u64,
    pub last_update: i64,
}

/// `GET /stats/upstreams` and `GET /stats/database/upstreams` — stats.yaml:575.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsUpstreams {
    pub upstreams: Vec<Upstream>,
    pub forwarded_queries: i64,
    pub total_queries: i64,
    pub took: Option<f64>,
}

/// One upstream destination — stats.yaml:582.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub ip: Option<String>,
    pub name: Option<String>,
    pub port: i64,
    pub count: u64,
    pub statistics: UpstreamStatistics,
}

/// `statistics` of an upstream (seconds) — stats.yaml:602.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamStatistics {
    pub response: f64,
    pub variance: f64,
}

/// `GET /stats/top_domains` and `GET /stats/database/top_domains` — stats.yaml:621.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsTopDomains {
    pub domains: Vec<TopDomain>,
    pub total_queries: i64,
    pub blocked_queries: i64,
    pub took: Option<f64>,
}

/// One top domain — stats.yaml:629.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopDomain {
    pub domain: String,
    pub count: u64,
}

/// `GET /stats/top_clients` — stats.yaml:646.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsTopClients {
    pub clients: Vec<TopClient>,
    pub total_queries: i64,
    pub blocked_queries: i64,
    pub took: Option<f64>,
}

/// One top client — stats.yaml:654.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopClient {
    pub ip: String,
    pub name: String,
    pub count: u64,
}

/// `GET /stats/database/top_clients` — stats.yaml:646 (via stats.yaml:246).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsDatabaseTopClients {
    pub clients: Vec<DatabaseTopClient>,
    pub total_queries: i64,
    pub blocked_queries: i64,
    pub took: Option<f64>,
}

/// One top client from the long-term database — stats.yaml:654.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatabaseTopClient {
    pub ip: String,
    // C (stats_database.c api_stats_database_top_items) emits null when the stored name is NULL; YAML says string.
    pub name: Option<String>,
    pub count: u64,
}

/// `GET /stats/query_types` and `GET /stats/database/query_types` — stats.yaml:675.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsQueryTypes {
    pub types: QueryTypeCounts,
    pub took: Option<f64>,
}

/// `GET /stats/recent_blocked` — stats.yaml:765.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsRecentBlocked {
    pub blocked: Vec<String>,
    pub took: Option<f64>,
}

/// `GET /stats/database/summary` — stats.yaml:746.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatsDatabaseSummary {
    pub sum_queries: u64,
    pub sum_blocked: u64,
    pub percent_blocked: f64,
    pub total_clients: u64,
    pub took: Option<f64>,
}

/// `GET /stats/database/top_domains` — stats.yaml:621 (via stats.yaml:188).
pub type StatsDatabaseTopDomains = StatsTopDomains;

/// `GET /stats/database/upstreams` — stats.yaml:575 (via stats.yaml:103).
pub type StatsDatabaseUpstreams = StatsUpstreams;

/// `GET /stats/database/query_types` — stats.yaml:675 (via stats.yaml:299).
pub type StatsDatabaseQueryTypes = StatsQueryTypes;

// ---------------------------------------------------------------------------
// /history
// ---------------------------------------------------------------------------

/// `GET /history` — history.yaml:121.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    pub history: Vec<HistoryEntry>,
    pub took: Option<f64>,
}

/// One `/history` bucket — history.yaml:128.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryEntry {
    pub timestamp: f64,
    pub total: u64,
    pub cached: u64,
    pub blocked: u64,
    pub forwarded: u64,
}

/// `GET /history/clients` — history.yaml:156.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryClients {
    // Keyed by client IP; C (history.c api_history_clients) keys the aggregate "others", the YAML example shows "0.0.0.0".
    pub clients: HashMap<String, HistoryClient>,
    pub history: Vec<HistoryClientsEntry>,
    pub took: Option<f64>,
}

/// One client of `/history/clients` — history.yaml:163.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryClient {
    pub name: Option<String>,
    pub total: u64,
}

/// One `/history/clients` bucket — history.yaml:192.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryClientsEntry {
    pub timestamp: f64,
    pub data: HashMap<String, u64>,
}

// ---------------------------------------------------------------------------
// /queries
// ---------------------------------------------------------------------------

/// `GET /queries` — queries.yaml:164.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Queries {
    pub queries: Vec<Query>,
    pub cursor: Option<i64>,
    #[serde(rename = "recordsTotal")]
    pub records_total: u64,
    #[serde(rename = "recordsFiltered")]
    pub records_filtered: u64,
    pub draw: i64,
    pub earliest_timestamp: f64,
    pub earliest_timestamp_disk: f64,
    pub took: Option<f64>,
}

/// One query of `/queries` — queries.yaml:171.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub id: i64,
    pub time: f64,
    #[serde(rename = "type")]
    pub query_type: String,
    pub domain: String,
    pub cname: Option<String>,
    pub status: Option<QueryStatus>,
    pub client: QueryClient,
    pub dnssec: Option<DnssecStatus>,
    pub reply: QueryReply,
    pub list_id: Option<i64>,
    pub upstream: Option<String>,
    pub ede: QueryEde,
}

/// `client` of a query — queries.yaml:193.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryClient {
    pub ip: String,
    pub name: Option<String>,
}

/// `reply` of a query — queries.yaml:207.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryReply {
    #[serde(rename = "type")]
    pub reply_type: Option<ReplyType>,
    // C (queries.c api_queries) emits the database `reply_time` column, which is seconds; YAML says ms.
    pub time: f64,
}

/// `ede` of a query — queries.yaml:225.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryEde {
    pub code: i64,
    pub text: Option<String>,
}

/// `GET /queries/suggestions` — queries.yaml:297.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueriesSuggestions {
    pub suggestions: Suggestions,
    pub took: Option<f64>,
}

/// `suggestions` object — queries.yaml:300.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suggestions {
    pub domain: Vec<String>,
    pub client_ip: Vec<String>,
    pub client_name: Vec<String>,
    pub upstream: Vec<String>,
    #[serde(rename = "type")]
    pub query_type: Vec<String>,
    pub status: Vec<String>,
    pub reply: Vec<String>,
    pub dnssec: Vec<String>,
}

// ---------------------------------------------------------------------------
// /search
// ---------------------------------------------------------------------------

/// `GET /search/{domain}` — search.yaml:40.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Search {
    pub search: SearchData,
    pub took: Option<f64>,
}

/// `search` object — search.yaml:43.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchData {
    pub domains: Vec<SearchDomain>,
    pub gravity: Vec<SearchGravity>,
    pub parameters: SearchParameters,
    pub results: SearchResults,
}

/// Domain-list match — search.yaml:46.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchDomain {
    pub domain: String,
    #[serde(deserialize_with = "required_nullable")]
    pub comment: Option<String>,
    pub enabled: bool,
    #[serde(rename = "type")]
    pub domain_type: DomainType,
    pub kind: DomainKind,
    pub id: i64,
    pub date_added: i64,
    pub date_modified: i64,
    pub groups: Vec<i64>,
}

/// Gravity (list) match — search.yaml:95.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchGravity {
    pub domain: String,
    pub address: String,
    #[serde(deserialize_with = "required_nullable")]
    pub comment: Option<String>,
    pub enabled: bool,
    pub id: i64,
    #[serde(rename = "type")]
    pub list_type: ListType,
    pub date_added: i64,
    pub date_modified: i64,
    pub date_updated: i64,
    pub number: u64,
    pub invalid_domains: u64,
    pub abp_entries: u64,
    pub status: i64,
    pub groups: Vec<i64>,
}

/// `search.parameters` — search.yaml:160.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchParameters {
    pub partial: bool,
    #[serde(rename = "N")]
    pub n: u64,
    pub domain: String,
    pub debug: bool,
}

/// `search.results` — search.yaml:179.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResults {
    pub domains: SearchResultsDomains,
    pub gravity: SearchResultsGravity,
    pub total: u64,
}

/// `search.results.domains` — search.yaml:182.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResultsDomains {
    pub exact: u64,
    pub regex: u64,
}

/// `search.results.gravity` — search.yaml:193.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SearchResultsGravity {
    pub allow: u64,
    pub block: u64,
}

// ---------------------------------------------------------------------------
// CRUD: domains, lists, groups, clients
// ---------------------------------------------------------------------------

/// `processed` of a POST/PUT reply — domains.yaml:425 (same in lists/groups/clients).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Processed {
    pub success: Vec<ProcessedSuccess>,
    pub errors: Vec<ProcessedError>,
}

/// `processed.success[]` — domains.yaml:436.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessedSuccess {
    pub item: String,
}

/// `processed.errors[]` — domains.yaml:446.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessedError {
    pub item: String,
    pub error: String,
}

/// `GET /domains[/{type}[/{kind}[/{domain}]]]` — domains.yaml:308.
// C (api_list.c api_list_read) only adds `processed` on writes; the YAML GET example shows `processed: null`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainsReply {
    pub domains: Vec<DomainEntry>,
    pub took: Option<f64>,
}

/// `POST /domains/{type}/{kind}` (201) and `PUT /domains/{type}/{kind}/{domain}` (200) — domains.yaml:91,196.
// C (api_list.c api_list_write) always sends a `processed` object on writes; YAML marks it nullable.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainsWriteReply {
    pub domains: Vec<DomainEntry>,
    pub processed: Processed,
    pub took: Option<f64>,
}

/// One domain-list entry — domains.yaml:315.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainEntry {
    pub domain: String,
    pub unicode: String,
    #[serde(rename = "type")]
    pub domain_type: DomainType,
    pub kind: DomainKind,
    #[serde(deserialize_with = "required_nullable")]
    pub comment: Option<String>,
    pub groups: Vec<i64>,
    pub enabled: bool,
    pub id: i64,
    pub date_added: i64,
    pub date_modified: i64,
}

/// `GET /lists[/{list}]` — lists.yaml:285.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListsReply {
    pub lists: Vec<ListEntry>,
    pub took: Option<f64>,
}

/// `POST /lists` (201) and `PUT /lists/{list}` (200) — lists.yaml:66,196.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListsWriteReply {
    pub lists: Vec<ListEntry>,
    pub processed: Processed,
    pub took: Option<f64>,
}

/// One list entry — lists.yaml:292.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListEntry {
    pub address: String,
    #[serde(rename = "type")]
    pub list_type: ListType,
    #[serde(deserialize_with = "required_nullable")]
    pub comment: Option<String>,
    pub groups: Vec<i64>,
    pub enabled: bool,
    pub id: i64,
    pub date_added: i64,
    pub date_modified: i64,
    pub date_updated: i64,
    pub number: u64,
    pub invalid_domains: u64,
    pub abp_entries: u64,
    pub status: i64,
}

/// `GET /groups[/{name}]` — groups.yaml:267.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupsReply {
    pub groups: Vec<GroupEntry>,
    pub took: Option<f64>,
}

/// `POST /groups` (201) and `PUT /groups/{name}` (200) — groups.yaml:63,182.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupsWriteReply {
    pub groups: Vec<GroupEntry>,
    pub processed: Processed,
    pub took: Option<f64>,
}

/// One group entry — groups.yaml:273.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupEntry {
    pub name: String,
    #[serde(deserialize_with = "required_nullable")]
    pub comment: Option<String>,
    pub enabled: bool,
    pub id: i64,
    pub date_added: i64,
    pub date_modified: i64,
}

/// `GET /clients[/{client}]` — clients.yaml:304.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientsReply {
    pub clients: Vec<ClientEntry>,
    pub took: Option<f64>,
}

/// `POST /clients` (201) and `PUT /clients/{client}` (200) — clients.yaml:64,213.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientsWriteReply {
    pub clients: Vec<ClientEntry>,
    pub processed: Processed,
    pub took: Option<f64>,
}

/// One client entry (no `enabled`) — clients.yaml:311.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientEntry {
    pub client: String,
    pub name: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub comment: Option<String>,
    pub groups: Vec<i64>,
    pub id: i64,
    pub date_added: i64,
    pub date_modified: i64,
}

/// `GET /clients/_suggestions` — clients.yaml:325.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSuggestions {
    pub clients: Vec<ClientSuggestion>,
    pub took: Option<f64>,
}

/// One unconfigured client suggestion — clients.yaml:331.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSuggestion {
    pub hwaddr: Option<String>,
    #[serde(rename = "macVendor")]
    pub mac_vendor: Option<String>,
    #[serde(rename = "lastQuery")]
    pub last_query: i64,
    pub addresses: Option<String>,
    pub names: Option<String>,
}

// ---------------------------------------------------------------------------
// /padd
// ---------------------------------------------------------------------------

/// `GET /padd` — padd.yaml:39 + info.yaml:394 (`system`) + info.yaml:1019 (`version`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Padd {
    // C (padd.c api_padd) always adds the four tops, as null when there are none.
    #[serde(deserialize_with = "required_nullable")]
    pub recent_blocked: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub top_domain: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub top_blocked: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub top_client: Option<String>,
    pub active_clients: u64,
    pub gravity_size: u64,
    pub blocking: BlockingStatus,
    pub queries: PaddQueries,
    pub cache: PaddCache,
    pub system: SystemData,
    pub node_name: String,
    // C (info.c read_sys_property) answers null, never omits the key.
    #[serde(deserialize_with = "required_nullable")]
    pub host_model: Option<String>,
    // C (padd.c api_padd) only adds `iface` and `version` when `full` is true (the default).
    pub iface: Option<PaddIface>,
    pub version: Option<VersionData>,
    pub config: PaddConfig,
    #[serde(rename = "%cpu")]
    pub cpu_percent: f64,
    #[serde(rename = "%mem")]
    pub mem_percent: f64,
    pub pid: i64,
    pub sensors: PaddSensors,
    pub took: Option<f64>,
}

/// `queries` of `/padd` — padd.yaml:74.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddQueries {
    pub total: u64,
    pub blocked: u64,
    pub percent_blocked: f64,
    pub query_frequency: f64,
}

/// `cache` of `/padd` — padd.yaml:93.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddCache {
    pub size: u64,
    pub inserted: u64,
    pub evicted: u64,
}

/// `iface` of `/padd` — padd.yaml:108.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddIface {
    pub v4: PaddIfaceV4,
    pub v6: PaddIfaceV6,
}

/// `iface.v4` — padd.yaml:112.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddIfaceV4 {
    pub addr: Option<String>,
    pub rx_bytes: Option<PaddByteCount>,
    pub tx_bytes: Option<PaddByteCount>,
    pub num_addrs: u64,
    // C (padd.c api_padd) emits null `name` when no gateway was found; YAML says string.
    pub name: Option<String>,
    pub gw_addr: Option<String>,
}

/// `iface.v6` — padd.yaml:154.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddIfaceV6 {
    pub addr: Option<String>,
    pub num_addrs: u64,
    // C (padd.c api_padd) emits null `name` when no gateway was found; YAML says string.
    pub name: Option<String>,
    pub gw_addr: Option<String>,
}

/// `iface.v4.{rx,tx}_bytes` — padd.yaml:121.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddByteCount {
    pub value: f64,
    pub unit: String,
}

/// `config` of `/padd` — padd.yaml:185.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddConfig {
    pub dhcp_active: bool,
    pub dhcp_start: String,
    pub dhcp_end: String,
    pub dhcp_ipv6: bool,
    pub dns_domain: String,
    pub dns_port: u64,
    pub dns_num_upstreams: u64,
    pub dns_dnssec: bool,
    #[serde(rename = "dns_revServer_active")]
    pub dns_rev_server_active: bool,
    pub privacy_level: i64,
}

/// `sensors` of `/padd` — padd.yaml:241.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaddSensors {
    // C (info.c get_sensors_obj) adds null when no CPU sensor is found.
    #[serde(deserialize_with = "required_nullable")]
    pub cpu_temp: Option<f64>,
    pub hot_limit: f64,
    pub unit: String,
}

// ---------------------------------------------------------------------------
// /network
// ---------------------------------------------------------------------------

/// `GET /network/gateway` — network.c:35-118 (get_gateway, not detailed).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkGateway {
    pub gateway: Vec<GatewayEntry>,
    pub took: Option<f64>,
}

/// `gateway[]` — network.c:58-99.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayEntry {
    pub family: String,
    // C: JSON_COPY_STR_TO_OBJECT sends null for a route without one.
    #[serde(deserialize_with = "required_nullable")]
    pub interface: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub address: Option<String>,
    pub local: Vec<String>,
}

/// `GET /network/routes` — network.c:131-145, netlink.c:179-446.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkRoutes {
    pub routes: Vec<Route>,
    pub took: Option<f64>,
}

/// `routes[]` — netlink.c nlparsemsg_route without `detailed`: the first six
/// keys and `dst` are always there, the rest only with their attribute.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub table: u32,
    pub family: String,
    pub protocol: String,
    pub scope: String,
    #[serde(rename = "type")]
    pub route_type: String,
    pub flags: Vec<String>,
    pub dst: String,
    pub src: Option<String>,
    pub gateway: Option<String>,
    pub prefsrc: Option<String>,
    pub newdst: Option<String>,
    pub via: Option<String>,
    pub oif: Option<String>,
    pub iif: Option<String>,
    pub priority: Option<u32>,
    pub pref: Option<u8>,
}

/// `GET /network/interfaces` — network.c:147-162, netlink.c nllinks + nladdrs.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterfaces {
    pub interfaces: Vec<NetworkInterface>,
    pub took: Option<f64>,
}

/// `interfaces[]` — netlink.c:679-1330 (nlparsemsg_link, not detailed).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterface {
    pub name: String,
    #[serde(deserialize_with = "required_nullable")]
    pub speed: Option<i64>,
    #[serde(rename = "type")]
    pub link_type: Option<String>,
    pub flags: Vec<String>,
    pub state: Option<String>,
    pub carrier: Option<bool>,
    pub proto_down: Option<bool>,
    pub address: Option<String>,
    pub broadcast: Option<String>,
    pub perm_address: Option<String>,
    pub stats: Option<InterfaceStats>,
    pub addresses: Option<Vec<InterfaceAddress>>,
}

/// `interfaces[].stats` — netlink.c:950-974 (stats64; YAML lacks `bits`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceStats {
    pub rx_bytes: PaddByteCount,
    pub tx_bytes: PaddByteCount,
    pub bits: u8,
}

/// `interfaces[].addresses[]` — netlink.c:448-677 (nlparsemsg_address).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceAddress {
    pub family: String,
    pub scope: String,
    pub flags: Vec<String>,
    pub prefixlen: u8,
    pub address: Option<String>,
    pub address_type: Option<String>,
    pub local: Option<String>,
    pub local_type: Option<String>,
    pub broadcast: Option<String>,
    pub broadcast_type: Option<String>,
    pub anycast: Option<String>,
    pub anycast_type: Option<String>,
    pub label: Option<String>,
    pub prefered: Option<u64>,
    pub valid: Option<u64>,
    pub cstamp: Option<f64>,
    pub tstamp: Option<f64>,
}

// ---------------------------------------------------------------------------
// /endpoints
// ---------------------------------------------------------------------------

/// `GET /endpoints` — endpoints.yaml:30.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoints {
    pub endpoints: EndpointsByMethod,
    pub took: Option<f64>,
}

/// `endpoints` object — endpoints.yaml:33.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointsByMethod {
    pub get: Vec<Endpoint>,
    pub post: Vec<Endpoint>,
    pub put: Vec<Endpoint>,
    pub patch: Vec<Endpoint>,
    pub delete: Vec<Endpoint>,
}

/// One endpoint — endpoints.yaml:40.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub uri: String,
    pub parameters: String,
}
