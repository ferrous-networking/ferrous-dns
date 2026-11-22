use super::health::no_route_error;
use super::{HealthChecker, PoolManager, ServerStatus};
use ferrous_dns_application::ports::{
    AggregateStatus, IpFamily, ResolvedEndpointHealth, UpstreamGroupHealth, UpstreamHealthPort,
    UpstreamStatus,
};
use ferrous_dns_domain::DnsProtocol;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct UpstreamHealthAdapter {
    pool_manager: Arc<PoolManager>,
    health_checker: Option<Arc<HealthChecker>>,
}

impl UpstreamHealthAdapter {
    pub fn new(pool_manager: Arc<PoolManager>, health_checker: Option<Arc<HealthChecker>>) -> Self {
        Self {
            pool_manager,
            health_checker,
        }
    }
}

impl UpstreamHealthPort for UpstreamHealthAdapter {
    fn get_all_upstream_status(&self) -> Vec<(String, UpstreamStatus)> {
        let Some(checker) = &self.health_checker else {
            return Vec::new();
        };

        self.pool_manager
            .get_all_arc_protocols()
            .into_iter()
            .map(|protocol| {
                let status = map_server_status(checker.get_status(&protocol));
                (protocol.to_string(), status)
            })
            .collect()
    }

    fn get_grouped_upstream_health(&self) -> Vec<UpstreamGroupHealth> {
        let checker: Option<&HealthChecker> = self.health_checker.as_deref();

        self.pool_manager
            .get_pool_groups()
            .into_iter()
            .map(|e| {
                let resolved: Vec<ResolvedEndpointHealth> = e
                    .protocols
                    .iter()
                    .flat_map(|p| match checker.and_then(|c| c.get_health_info(p)) {
                        Some(health) => expand_endpoint_health(
                            p,
                            map_server_status(health.status),
                            health.last_check_latency_ms,
                            health.last_error,
                            health.consecutive_failures,
                            &health.unroutable,
                        ),
                        None => {
                            expand_endpoint_health(p, UpstreamStatus::Unknown, None, None, 0, &[])
                        }
                    })
                    .collect();

                UpstreamGroupHealth {
                    address: e.original.to_string(),
                    status: aggregate_status(&resolved),
                    resolved,
                    pool_name: e.pool_name.to_string(),
                    strategy: e.strategy,
                }
            })
            .collect()
    }
}

/// Expands one `DnsProtocol` into one or more `ResolvedEndpointHealth` entries.
///
/// For HTTPS/H3, the protocol stores multiple pre-resolved `SocketAddr`s internally.
/// Each is surfaced as a separate entry — all sharing the same health status, since
/// the health checker tracks health per-URL (not per-IP) for these transports.
/// The exception is an address this host has no route to, which reads as such.
/// For UDP/TCP/TLS/Quic, the protocol maps to a single resolved socket address.
fn expand_endpoint_health(
    p: &DnsProtocol,
    status: UpstreamStatus,
    latency_ms: Option<u64>,
    last_error: Option<String>,
    consecutive_failures: u16,
    unroutable: &[SocketAddr],
) -> Vec<ResolvedEndpointHealth> {
    let pre_resolved = https_resolved_addrs(p);
    if !pre_resolved.is_empty() {
        return pre_resolved
            .iter()
            .map(|addr| {
                if unroutable.contains(addr) {
                    return ResolvedEndpointHealth {
                        address: addr.to_string(),
                        family: addr_family(*addr),
                        status: UpstreamStatus::Unhealthy,
                        latency_ms: None,
                        last_error: Some(no_route_error(&[*addr])),
                        consecutive_failures: 0,
                        no_route: true,
                    };
                }
                ResolvedEndpointHealth {
                    address: addr.to_string(),
                    family: addr_family(*addr),
                    status,
                    latency_ms,
                    last_error: last_error.clone(),
                    consecutive_failures,
                    no_route: false,
                }
            })
            .collect();
    }

    vec![ResolvedEndpointHealth {
        address: single_endpoint_address(p),
        family: single_ip_family(p),
        status,
        latency_ms,
        last_error,
        consecutive_failures,
        no_route: !unroutable.is_empty(),
    }]
}

fn https_resolved_addrs(p: &DnsProtocol) -> &[SocketAddr] {
    match p {
        DnsProtocol::Https { resolved_addrs, .. } | DnsProtocol::H3 { resolved_addrs, .. } => {
            resolved_addrs.as_slice()
        }
        _ => &[],
    }
}

fn single_endpoint_address(p: &DnsProtocol) -> String {
    match p.socket_addr() {
        Some(addr) => addr.to_string(),
        None => p.to_string(),
    }
}

fn single_ip_family(p: &DnsProtocol) -> IpFamily {
    match p.socket_addr() {
        Some(addr) => addr_family(addr),
        None => IpFamily::Unknown,
    }
}

fn addr_family(addr: SocketAddr) -> IpFamily {
    if addr.is_ipv4() {
        IpFamily::Ipv4
    } else {
        IpFamily::Ipv6
    }
}

fn map_server_status(s: ServerStatus) -> UpstreamStatus {
    match s {
        ServerStatus::Healthy => UpstreamStatus::Healthy,
        ServerStatus::Unhealthy | ServerStatus::NoRoute => UpstreamStatus::Unhealthy,
        ServerStatus::Unknown => UpstreamStatus::Unknown,
    }
}

/// The status of a server from the endpoints this host has a route to. With
/// a route to none, the server cannot answer at all.
fn aggregate_status(resolved: &[ResolvedEndpointHealth]) -> AggregateStatus {
    if resolved.is_empty() {
        return AggregateStatus::Unknown;
    }
    let routable: Vec<&ResolvedEndpointHealth> = resolved.iter().filter(|r| !r.no_route).collect();
    if routable.is_empty() {
        return AggregateStatus::Unhealthy;
    }
    let healthy = routable
        .iter()
        .filter(|r| matches!(r.status, UpstreamStatus::Healthy))
        .count();
    let unhealthy = routable
        .iter()
        .filter(|r| matches!(r.status, UpstreamStatus::Unhealthy))
        .count();

    match (healthy, unhealthy, routable.len()) {
        (0, 0, _) => AggregateStatus::Unknown,
        (h, 0, total) if h == total => AggregateStatus::Healthy,
        (0, _, _) => AggregateStatus::Unhealthy,
        _ => AggregateStatus::Partial,
    }
}
