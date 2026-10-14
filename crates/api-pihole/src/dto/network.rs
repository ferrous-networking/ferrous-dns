use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::padd::PaddByteCount;

/// Pi-hole v6 GET /api/network/gateway response.
#[derive(Debug, Serialize, ToSchema)]
pub struct GatewayResponse {
    pub gateway: Vec<GatewayEntry>,
}

/// One default route.
#[derive(Debug, Serialize, ToSchema)]
pub struct GatewayEntry {
    /// `inet` or `inet6`.
    pub family: &'static str,
    pub interface: String,
    /// The next hop, null for a route without one.
    pub address: Option<String>,
    /// The interface's own addresses of the same family.
    pub local: Vec<String>,
}

/// Pi-hole v6 GET /api/network/routes response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RoutesResponse {
    pub routes: Vec<RouteEntry>,
}

/// One route of the kernel's routing tables.
#[derive(Debug, Serialize, ToSchema)]
pub struct RouteEntry {
    /// 254 for the main table, 255 for the local one.
    pub table: u32,
    pub family: &'static str,
    /// How the route was installed; the kernel's route tables do not say, so
    /// `unspec`.
    pub protocol: &'static str,
    pub scope: &'static str,
    #[serde(rename = "type")]
    pub route_type: &'static str,
    /// `linkdown` when the interface has no carrier.
    pub flags: Vec<&'static str>,
    /// Destination address without its prefix length, or `default`.
    pub dst: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
    pub oif: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u32>,
    /// IPv6 router preference; 0 (medium).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pref: Option<u8>,
}

/// Pi-hole v6 GET /api/network/interfaces response.
#[derive(Debug, Serialize, ToSchema)]
pub struct InterfacesResponse {
    pub interfaces: Vec<InterfaceEntry>,
}

/// One network interface.
#[derive(Debug, Serialize, ToSchema)]
pub struct InterfaceEntry {
    pub name: String,
    /// Link speed in Mbit/s, null when the link reports none.
    pub speed: Option<i64>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub link_type: Option<&'static str>,
    pub flags: Vec<&'static str>,
    pub state: String,
    pub carrier: bool,
    pub proto_down: bool,
    /// Hardware address, sent only for 6-byte (EUI-48) addresses.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast: Option<String>,
    pub stats: InterfaceStats,
    /// Left out when the interface has no address.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<InterfaceAddress>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct InterfaceStats {
    pub rx_bytes: PaddByteCount,
    pub tx_bytes: PaddByteCount,
    /// Width of the kernel's counters.
    pub bits: u8,
}

/// One address of an interface. The kernel's address flags and lifetimes
/// are not read, so `flags` is empty and the lifetimes are left out.
#[derive(Debug, Serialize, ToSchema)]
pub struct InterfaceAddress {
    pub family: &'static str,
    pub scope: &'static str,
    pub flags: Vec<&'static str>,
    pub prefixlen: u8,
    pub address: String,
    pub address_type: &'static str,
    /// IPv4 only, as the kernel reports it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_type: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broadcast_type: Option<&'static str>,
    /// IPv4 only: the interface name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Query of `GET /api/network/devices`, with network.c's defaults.
#[derive(Debug, Deserialize)]
pub struct DevicesQuery {
    pub max_devices: Option<u32>,
    pub max_addresses: Option<u32>,
}

/// Pi-hole v6 GET /api/network/devices response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DevicesResponse {
    pub devices: Vec<DeviceEntry>,
}

/// A device: the clients that share a hardware address.
#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceEntry {
    /// The lowest client id of the device.
    pub id: i64,
    /// The MAC address, or `ip-<address>` without one.
    pub hwaddr: String,
    /// Not known, so `""`.
    pub interface: String,
    #[serde(rename = "firstSeen")]
    pub first_seen: i64,
    #[serde(rename = "lastQuery")]
    pub last_query: i64,
    #[serde(rename = "numQueries")]
    pub num_queries: u64,
    /// No vendor database, so `""`.
    #[serde(rename = "macVendor")]
    pub mac_vendor: String,
    /// Most recently seen first.
    pub ips: Vec<DeviceAddress>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceAddress {
    pub ip: String,
    pub name: Option<String>,
    #[serde(rename = "lastSeen")]
    pub last_seen: i64,
    #[serde(rename = "nameUpdated")]
    pub name_updated: i64,
}
