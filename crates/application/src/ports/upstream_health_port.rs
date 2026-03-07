use ferrous_dns_domain::UpstreamStrategy;

/// Status of an upstream DNS server.
#[derive(Debug, Clone, Copy)]
pub enum UpstreamStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

/// Aggregate health status for a server that resolves to multiple IP endpoints.
///
/// `Partial` means at least one endpoint is healthy and at least one is not —
/// typically one address family works and the other does not.
#[derive(Debug, Clone, Copy)]
pub enum AggregateStatus {
    /// All resolved endpoints are healthy.
    Healthy,
    /// Some endpoints are healthy and some are not (e.g. IPv4 ok, IPv6 failing).
    Partial,
    /// All resolved endpoints are unhealthy.
    Unhealthy,
    /// No health data available yet (health check disabled or not yet run).
    Unknown,
}

/// IP address family of a resolved endpoint.
#[derive(Debug, Clone, Copy)]
pub enum IpFamily {
    Ipv4,
    Ipv6,
    /// Address could not be classified (e.g. hostname not yet resolved).
    Unknown,
}

/// Health details for a single resolved IP endpoint.
#[derive(Debug, Clone)]
pub struct ResolvedEndpointHealth {
    /// IP:port string (e.g. "1.1.1.1:853" or "[2606:4700::1111]:853").
    pub address: String,
    pub family: IpFamily,
    pub status: UpstreamStatus,
    pub latency_ms: Option<u64>,
    pub last_error: Option<String>,
    pub consecutive_failures: u16,
}

/// Grouped health for one configured upstream server, with per-IP endpoint breakdown.
#[derive(Debug, Clone)]
pub struct UpstreamGroupHealth {
    /// Original configured address (e.g. "doq://dns.alidns.com:853").
    pub address: String,
    /// Aggregate status computed from all resolved endpoints.
    pub status: AggregateStatus,
    /// One entry per resolved IP address.
    pub resolved: Vec<ResolvedEndpointHealth>,
    /// Name of the pool this server belongs to.
    pub pool_name: String,
    /// Strategy of the pool.
    pub strategy: UpstreamStrategy,
}

/// Port for querying upstream DNS server health status.
pub trait UpstreamHealthPort: Send + Sync {
    /// Returns a flat list of (server_address, status) pairs.
    /// Kept for backward compatibility with existing callers.
    fn get_all_upstream_status(&self) -> Vec<(String, UpstreamStatus)>;

    /// Returns grouped health per configured server, with per-IP breakdown.
    fn get_grouped_upstream_health(&self) -> Vec<UpstreamGroupHealth>;
}
