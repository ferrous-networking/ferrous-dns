use std::net::IpAddr;

use axum::extract::Path;
use axum::http::StatusCode;
use axum::response::Response;
use axum::Json;

use crate::{dto::dhcp::LeasesResponse, errors::pihole_error_response};

/// Pi-hole v6 GET /api/dhcp/leases
///
/// Ferrous serves no DHCP, so the list is empty, as on a Pi-hole with its
/// DHCP server off.
#[utoipa::path(
    get,
    path = "/dhcp/leases",
    tag = "pihole:dhcp",
    responses(
        (status = 200, description = "Active DHCP leases, always none", body = LeasesResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_leases() -> Json<LeasesResponse> {
    Json(LeasesResponse { leases: Vec::new() })
}

/// Pi-hole v6 DELETE /api/dhcp/leases/{ip}
///
/// Refused as FTL refuses it with DHCP off: 400 "Failed to delete DHCP
/// lease", after the address itself has been checked.
#[utoipa::path(
    delete,
    path = "/dhcp/leases/{ip}",
    tag = "pihole:dhcp",
    params(("ip" = String, Path, description = "IP address of the lease")),
    responses(
        (status = 400, description = "Invalid address, or no DHCP server to delete the lease from")
    ),
    security(("session_id" = []))
)]
pub async fn delete_lease(Path(ip): Path<String>) -> Response {
    if ip.parse::<IpAddr>().is_err() {
        return pihole_error_response(
            StatusCode::BAD_REQUEST,
            "bad_request",
            "The provided IP address is invalid",
            Some(&ip),
        );
    }
    pihole_error_response(
        StatusCode::BAD_REQUEST,
        "bad_request",
        "Failed to delete DHCP lease",
        Some("DHCP is not enabled"),
    )
}
