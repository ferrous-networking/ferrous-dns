use ferrous_dns_application::ports::{ResolvedEndpointHealth, UpstreamGroupHealth};
use serde::Serialize;
use utoipa::ToSchema;

/// Per-IP endpoint detail within a server group.
#[derive(Debug, Serialize, ToSchema)]
pub struct ResolvedEndpointResponse {
    pub address: String,
    /// `ipv4`, `ipv6` or `unknown`.
    #[schema(value_type = String)]
    pub family: &'static str,
    /// `Healthy`, `Unhealthy` or `Unknown`.
    #[schema(value_type = String)]
    pub status: &'static str,
    pub latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub consecutive_failures: u16,
    /// This host has no route to the address, as in a container without
    /// IPv6. It is never dialed, reads `Unhealthy`, and does not count
    /// toward the server's `status`.
    pub no_route: bool,
}

impl From<ResolvedEndpointHealth> for ResolvedEndpointResponse {
    fn from(r: ResolvedEndpointHealth) -> Self {
        Self {
            address: r.address,
            family: r.family.as_str(),
            status: r.status.as_str(),
            latency_ms: r.latency_ms,
            last_error: r.last_error,
            consecutive_failures: r.consecutive_failures,
            no_route: r.no_route,
        }
    }
}

/// Grouped health: one entry per configured upstream server.
#[derive(Debug, Serialize, ToSchema)]
pub struct UpstreamGroupResponse {
    pub address: String,
    /// `Healthy`, `Partial`, `Unhealthy` or `Unknown`, over the endpoints
    /// this host has a route to.
    #[schema(value_type = String)]
    pub status: &'static str,
    pub resolved: Vec<ResolvedEndpointResponse>,
    pub pool_name: String,
    /// `Parallel`, `Failover` or `Balanced`.
    pub strategy: String,
}

impl From<UpstreamGroupHealth> for UpstreamGroupResponse {
    fn from(g: UpstreamGroupHealth) -> Self {
        Self {
            address: g.address,
            status: g.status.as_str(),
            resolved: g
                .resolved
                .into_iter()
                .map(ResolvedEndpointResponse::from)
                .collect(),
            pool_name: g.pool_name,
            strategy: g.strategy.to_string(),
        }
    }
}
