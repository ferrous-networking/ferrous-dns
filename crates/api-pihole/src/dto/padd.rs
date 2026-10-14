use serde::Serialize;
use utoipa::ToSchema;

use super::dns::BlockingStatus;
use super::info::{SystemInfo, VersionComponents};

/// Pi-hole v6 GET /api/padd response: the one-call summary PADD polls.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaddResponse {
    /// Most recently blocked domain, null when none.
    pub recent_blocked: Option<String>,
    /// Most queried allowed domain, null when none.
    pub top_domain: Option<String>,
    /// Most blocked domain, null when none.
    pub top_blocked: Option<String>,
    /// Most active client's name, or its IP without one; null when none.
    pub top_client: Option<String>,
    pub active_clients: u64,
    pub gravity_size: u64,
    pub blocking: BlockingStatus,
    pub queries: PaddQueries,
    pub cache: PaddCache,
    pub system: SystemInfo,
    pub node_name: String,
    /// Device-tree model, null where there is none (most x86 hosts).
    pub host_model: Option<String>,
    /// Only with `full`, as in FTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iface: Option<PaddIface>,
    /// Only with `full`, as in FTL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<VersionComponents>,
    pub config: PaddConfig,
    /// Ferrous does not sample its CPU time, so 0.
    #[serde(rename = "%cpu")]
    pub cpu_percent: f64,
    #[serde(rename = "%mem")]
    pub mem_percent: f64,
    pub pid: u32,
    pub sensors: PaddSensors,
}

/// Queries of the last 24 hours, as in `/stats/summary`.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaddQueries {
    pub total: u64,
    pub blocked: u64,
    pub percent_blocked: f64,
    pub query_frequency: f64,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaddCache {
    /// Configured cache capacity, 0 with the cache off.
    pub size: u64,
    /// Not tracked by Ferrous, so 0.
    pub inserted: u64,
    /// Not tracked by Ferrous, so 0.
    pub evicted: u64,
}

/// The interfaces of the default routes.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaddIface {
    pub v4: PaddIfaceV4,
    pub v6: PaddIfaceV6,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaddIfaceV4 {
    /// First IPv4 address of the interface.
    pub addr: Option<String>,
    /// Absent when the interface counters cannot be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bytes: Option<PaddByteCount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bytes: Option<PaddByteCount>,
    pub num_addrs: u64,
    /// Interface of the IPv4 default route, null without one.
    pub name: Option<String>,
    pub gw_addr: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaddIfaceV6 {
    /// First IPv6 address of the interface.
    pub addr: Option<String>,
    pub num_addrs: u64,
    /// Interface of the IPv6 default route, or the IPv4 one without it.
    pub name: Option<String>,
    pub gw_addr: Option<String>,
}

/// A byte count scaled by 1024 until it is at most 1024, as FTL prints it.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaddByteCount {
    pub value: f64,
    /// `""`, `k`, `M`, `G`, ...
    pub unit: String,
}

/// FTL's configuration excerpt, from Ferrous's equivalents.
#[derive(Debug, Serialize, ToSchema)]
pub struct PaddConfig {
    /// Ferrous serves no DHCP, so false.
    pub dhcp_active: bool,
    /// Ferrous serves no DHCP, so empty.
    pub dhcp_start: String,
    /// Ferrous serves no DHCP, so empty.
    pub dhcp_end: String,
    /// Ferrous serves no DHCP, so false.
    pub dhcp_ipv6: bool,
    /// `[dns] local_domain`, empty without one.
    pub dns_domain: String,
    pub dns_port: u16,
    pub dns_num_upstreams: u64,
    /// Whether DNSSEC validation is on.
    pub dns_dnssec: bool,
    /// Whether conditional forwarding (`local_dns_server`) is set.
    #[serde(rename = "dns_revServer_active")]
    pub dns_rev_server_active: bool,
    /// Ferrous has no privacy levels, so 0 (show everything).
    pub privacy_level: u8,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PaddSensors {
    /// First temperature of the CPU sensor, null when none is found.
    pub cpu_temp: Option<f64>,
    /// FTL's default `webserver.api.temp.limit`; Ferrous has no such setting.
    pub hot_limit: f64,
    pub unit: &'static str,
}
