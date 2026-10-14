use serde::Serialize;
use utoipa::ToSchema;

/// Pi-hole v6 GET /api/dhcp/leases response.
#[derive(Debug, Serialize, ToSchema)]
pub struct LeasesResponse {
    pub leases: Vec<DhcpLease>,
}

/// One DHCP lease (dhcp.yaml). Ferrous serves no DHCP, so none is listed.
#[derive(Debug, Serialize, ToSchema)]
pub struct DhcpLease {
    /// Expiry as a Unix timestamp, 0 for an infinite lease.
    pub expires: i64,
    pub name: String,
    pub hwaddr: String,
    pub ip: String,
    pub clientid: String,
}
