use super::{HealthChecker, PoolGroupEntry, PoolManager, ServerStatus};
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
                let status = match checker.get_status(&protocol) {
                    ServerStatus::Healthy => UpstreamStatus::Healthy,
                    ServerStatus::Unhealthy => UpstreamStatus::Unhealthy,
                    ServerStatus::Unknown => UpstreamStatus::Unknown,
                };
                (protocol.to_string(), status)
            })
            .collect()
    }

    fn get_grouped_upstream_health(&self) -> Vec<UpstreamGroupHealth> {
        let Some(checker) = &self.health_checker else {
            return self
                .pool_manager
                .get_pool_groups()
                .into_iter()
                .map(|e: PoolGroupEntry| {
                    let resolved = e
                        .protocols
                        .iter()
                        .flat_map(|p| {
                            expand_endpoint_health(p, UpstreamStatus::Unknown, None, None, 0)
                        })
                        .collect();
                    UpstreamGroupHealth {
                        address: e.original.to_string(),
                        status: AggregateStatus::Unknown,
                        resolved,
                        pool_name: e.pool_name.to_string(),
                        strategy: e.strategy,
                    }
                })
                .collect();
        };

        self.pool_manager
            .get_pool_groups()
            .into_iter()
            .map(|e: PoolGroupEntry| {
                let resolved: Vec<ResolvedEndpointHealth> = e
                    .protocols
                    .iter()
                    .flat_map(|p| {
                        let health = checker.get_health_info(p);
                        let status = map_server_status(checker.get_status(p));
                        expand_endpoint_health(
                            p,
                            status,
                            health.as_ref().and_then(|h| h.last_check_latency_ms),
                            health.as_ref().and_then(|h| h.last_error.clone()),
                            health.map(|h| h.consecutive_failures).unwrap_or(0),
                        )
                    })
                    .collect();

                let status = aggregate_status(&resolved);
                UpstreamGroupHealth {
                    address: e.original.to_string(),
                    status,
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
/// For UDP/TCP/TLS/Quic, the protocol maps to a single resolved socket address.
fn expand_endpoint_health(
    p: &DnsProtocol,
    status: UpstreamStatus,
    latency_ms: Option<u64>,
    last_error: Option<String>,
    consecutive_failures: u16,
) -> Vec<ResolvedEndpointHealth> {
    let pre_resolved = https_resolved_addrs(p);
    if !pre_resolved.is_empty() {
        return pre_resolved
            .iter()
            .map(|addr| ResolvedEndpointHealth {
                address: addr.to_string(),
                family: addr_family(*addr),
                status,
                latency_ms,
                last_error: last_error.clone(),
                consecutive_failures,
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
        ServerStatus::Unhealthy => UpstreamStatus::Unhealthy,
        ServerStatus::Unknown => UpstreamStatus::Unknown,
    }
}

fn aggregate_status(resolved: &[ResolvedEndpointHealth]) -> AggregateStatus {
    if resolved.is_empty() {
        return AggregateStatus::Unknown;
    }
    let healthy = resolved
        .iter()
        .filter(|r| matches!(r.status, UpstreamStatus::Healthy))
        .count();
    let unhealthy = resolved
        .iter()
        .filter(|r| matches!(r.status, UpstreamStatus::Unhealthy))
        .count();

    match (healthy, unhealthy, resolved.len()) {
        (0, 0, _) => AggregateStatus::Unknown,
        (h, 0, total) if h == total => AggregateStatus::Healthy,
        (0, _, _) => AggregateStatus::Unhealthy,
        _ => AggregateStatus::Partial,
    }
}
