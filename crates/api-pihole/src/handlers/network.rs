use axum::Json;
use ferrous_dns_domain::DomainError;

use crate::{
    dto::network::{GatewayResponse, InterfacesResponse, RoutesResponse},
    errors::PiholeApiError,
    network,
};

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
