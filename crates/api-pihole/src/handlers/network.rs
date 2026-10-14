use axum::extract::{Query, State};
use axum::Json;
use ferrous_dns_domain::{Client, DomainError};

use crate::{
    crud::unix_seconds,
    devices::{group_devices, Device},
    dto::network::{
        DeviceAddress, DeviceEntry, DevicesQuery, DevicesResponse, GatewayResponse,
        InterfacesResponse, RoutesResponse,
    },
    errors::PiholeApiError,
    network,
    state::PiholeAppState,
};

/// network.c's defaults for `max_devices` and `max_addresses`.
const DEFAULT_MAX_DEVICES: u32 = 10;
const DEFAULT_MAX_ADDRESSES: u32 = 3;

/// Runs a blocking read of the machine's network off the async workers.
async fn read<T: Send + 'static>(
    reader: impl FnOnce() -> T + Send + 'static,
) -> Result<T, PiholeApiError> {
    tokio::task::spawn_blocking(reader)
        .await
        .map_err(|e| PiholeApiError(DomainError::IoError(e.to_string())))
}

/// Pi-hole v6 GET /api/network/gateway
///
/// The default routes, each with its interface's addresses of the same
/// family. `detailed` is accepted and adds nothing.
#[utoipa::path(
    get,
    path = "/network/gateway",
    tag = "pihole:network",
    responses(
        (status = 200, description = "Default routes", body = GatewayResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_gateway() -> Result<Json<GatewayResponse>, PiholeApiError> {
    let gateway = read(|| network::gateways(&network::read_routes())).await?;
    Ok(Json(GatewayResponse { gateway }))
}

/// Pi-hole v6 GET /api/network/routes
///
/// The kernel's routes. Read from `/proc` rather than netlink, so the IPv4
/// local table is missing and `protocol` is `unspec`.
#[utoipa::path(
    get,
    path = "/network/routes",
    tag = "pihole:network",
    responses(
        (status = 200, description = "Routes", body = RoutesResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_routes() -> Result<Json<RoutesResponse>, PiholeApiError> {
    let routes = read(network::read_routes).await?;
    Ok(Json(RoutesResponse { routes }))
}

/// Pi-hole v6 GET /api/network/interfaces
///
/// Every interface from `/sys/class/net` with its addresses. Address flags
/// and lifetimes are not read.
#[utoipa::path(
    get,
    path = "/network/interfaces",
    tag = "pihole:network",
    responses(
        (status = 200, description = "Interfaces", body = InterfacesResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_interfaces() -> Result<Json<InterfacesResponse>, PiholeApiError> {
    let interfaces = read(network::read_interfaces).await?;
    Ok(Json(InterfacesResponse { interfaces }))
}

/// Pi-hole v6 GET /api/network/devices
///
/// FTL's network table, built from the clients the resolver knows: clients
/// that share a MAC address are one device, a client without one is a device
/// of its own. Most recently active first. The interface and the vendor are
/// not known, so `""`.
#[utoipa::path(
    get,
    path = "/network/devices",
    tag = "pihole:network",
    params(
        ("max_devices" = Option<u32>, Query, description = "Most devices to return (default 10)"),
        ("max_addresses" = Option<u32>, Query, description = "Most addresses per device (default 3)")
    ),
    responses(
        (status = 200, description = "Devices", body = DevicesResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_devices(
    State(state): State<PiholeAppState>,
    Query(query): Query<DevicesQuery>,
) -> Result<Json<DevicesResponse>, PiholeApiError> {
    let max_devices = query.max_devices.unwrap_or(DEFAULT_MAX_DEVICES) as usize;
    let max_addresses = query.max_addresses.unwrap_or(DEFAULT_MAX_ADDRESSES) as usize;
    let clients = state.clients.get_clients.get_all(u32::MAX, 0).await?;
    let devices = group_devices(&clients)
        .into_iter()
        .take(max_devices)
        .map(|device| device_entry(device, max_addresses))
        .collect();
    Ok(Json(DevicesResponse { devices }))
}

fn device_entry(device: Device<'_>, max_addresses: usize) -> DeviceEntry {
    let last_seen = |client: &&Client| unix_seconds(client.last_seen.as_deref());
    let mut clients = device.clients.clone();
    clients.sort_by_key(|client| std::cmp::Reverse(last_seen(client)));
    DeviceEntry {
        id: device
            .clients
            .iter()
            .filter_map(|c| c.id)
            .min()
            .unwrap_or(0),
        interface: String::new(),
        first_seen: device
            .clients
            .iter()
            .map(|c| unix_seconds(c.first_seen.as_deref()))
            .filter(|seen| *seen > 0)
            .min()
            .unwrap_or(0),
        last_query: device.last_query(),
        num_queries: device.clients.iter().map(|c| c.query_count).sum(),
        mac_vendor: String::new(),
        ips: clients
            .iter()
            .take(max_addresses)
            .map(|client| DeviceAddress {
                ip: client.ip_address.to_string(),
                name: client.hostname.as_deref().map(str::to_string),
                last_seen: last_seen(client),
                name_updated: client.last_hostname_update.unwrap_or(0),
            })
            .collect(),
        hwaddr: device.hwaddr,
    }
}
