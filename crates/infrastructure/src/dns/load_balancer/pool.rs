use super::balanced::BalancedStrategy;
use super::failover::FailoverStrategy;
use super::health::HealthChecker;
use super::parallel::ParallelStrategy;
use super::strategy::{QueryContext, Strategy, UpstreamResult};
use crate::dns::events::QueryEventEmitter;
use crate::dns::forwarding::{MessageBuilder, ResponseParser};
use crate::dns::transport::resolver;
use ferrous_dns_domain::{
    Config, DnsProtocol, DomainError, RecordType, UpstreamPool, UpstreamStrategy,
};
use smallvec::SmallVec;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

pub struct PoolManager {
    pools: Vec<PoolWithStrategy>,
    health_checker: Option<Arc<HealthChecker>>,
    emitter: QueryEventEmitter,
}

struct PoolWithStrategy {
    config: UpstreamPool,
    strategy: Strategy,
    server_protocols: Vec<Arc<DnsProtocol>>,
    name_arc: Arc<str>,
    server_displays: Arc<HashMap<Arc<DnsProtocol>, Arc<str>>>,
}

impl PoolManager {
    pub async fn new(
        pools: Vec<UpstreamPool>,
        health_checker: Option<Arc<HealthChecker>>,
        emitter: QueryEventEmitter,
    ) -> Result<Self, DomainError> {
        if pools.is_empty() {
            return Err(DomainError::InvalidDomainName(
                "At least one pool must be configured".into(),
            ));
        }

        let mut pools_with_strategy = Vec::new();
        for pool in pools {
            let strategy = match pool.strategy {
                UpstreamStrategy::Parallel => Strategy::Parallel(ParallelStrategy::new()),
                UpstreamStrategy::Balanced => Strategy::Balanced(BalancedStrategy::new()),
                UpstreamStrategy::Failover => Strategy::Failover(FailoverStrategy::new()),
            };

            let server_protocols: Result<Vec<DnsProtocol>, _> = pool
                .servers
                .iter()
                .map(|s| {
                    s.parse::<DnsProtocol>().map_err(|e| {
                        DomainError::InvalidDomainName(format!("Invalid endpoint '{}': {}", s, e))
                    })
                })
                .collect();

            let parsed = server_protocols?;
            let expanded = Self::expand_hostnames(parsed).await;

            let name_arc: Arc<str> = Arc::from(pool.name.as_str());
            let server_protocols: Vec<Arc<DnsProtocol>> =
                expanded.into_iter().map(Arc::new).collect();
            let server_displays: Arc<HashMap<Arc<DnsProtocol>, Arc<str>>> = Arc::new(
                server_protocols
                    .iter()
                    .map(|p| (Arc::clone(p), Arc::from(p.to_string())))
                    .collect(),
            );
            pools_with_strategy.push(PoolWithStrategy {
                config: pool,
                strategy,
                server_protocols,
                name_arc,
                server_displays,
            });
        }
        pools_with_strategy.sort_by_key(|p| p.config.priority);

        Ok(Self {
            pools: pools_with_strategy,
            health_checker,
            emitter,
        })
    }

    async fn expand_hostnames(protocols: Vec<DnsProtocol>) -> Vec<DnsProtocol> {
        let mut expanded = Vec::new();
        for protocol in protocols {
            if protocol.needs_resolution() {
                match &protocol {
                    DnsProtocol::Udp { addr }
                    | DnsProtocol::Tcp { addr }
                    | DnsProtocol::Tls { addr, .. }
                    | DnsProtocol::Quic { addr, .. } => {
                        let (hostname, port) = match addr.unresolved_parts() {
                            Some((h, p)) => (h.to_string(), p),
                            None => {
                                expanded.push(protocol);
                                continue;
                            }
                        };
                        match resolver::resolve_all(&hostname, port, Duration::from_secs(5)).await {
                            Ok(addrs) => {
                                let limited = Self::limit_resolved_addrs(addrs);
                                info!(
                                    "{} resolved to {} upstream servers (limited to {} per family)",
                                    hostname,
                                    limited.len(),
                                    4
                                );
                                for addr in &limited {
                                    let resolved = protocol.with_resolved_addr(*addr);
                                    info!("  → {}", resolved);
                                    expanded.push(resolved);
                                }
                            }
                            Err(e) => {
                                warn!(
                                    hostname = %hostname,
                                    error = %e,
                                    "Failed to resolve upstream hostname, keeping unresolved"
                                );
                                expanded.push(protocol);
                            }
                        }
                    }
                    DnsProtocol::Https { hostname, .. } | DnsProtocol::H3 { hostname, .. } => {
                        let host = hostname.to_string();
                        let port = Self::extract_port_from_hostname(&host, 443);
                        let clean_host = host.rsplit_once(':').map_or(host.as_str(), |(h, _)| h);
                        match resolver::resolve_all(clean_host, port, Duration::from_secs(5)).await
                        {
                            Ok(addrs) => {
                                let limited = Self::limit_resolved_addrs(addrs);
                                info!("{} pre-resolved to {} addresses", clean_host, limited.len());
                                for addr in &limited {
                                    info!("  → {}", addr);
                                }
                                expanded.push(protocol.with_resolved_addrs(limited));
                            }
                            Err(e) => {
                                warn!(
                                    hostname = %clean_host,
                                    error = %e,
                                    "Failed to pre-resolve, transport will resolve at runtime"
                                );
                                expanded.push(protocol);
                            }
                        }
                    }
                }
            } else {
                expanded.push(protocol);
            }
        }
        expanded
    }

    fn limit_resolved_addrs(addrs: Vec<SocketAddr>) -> Vec<SocketAddr> {
        const MAX_ADDRS_PER_FAMILY: usize = 4;
        let mut ipv4_count = 0usize;
        let mut ipv6_count = 0usize;
        addrs
            .into_iter()
            .filter(|addr| {
                if addr.is_ipv4() && ipv4_count < MAX_ADDRS_PER_FAMILY {
                    ipv4_count += 1;
                    true
                } else if addr.is_ipv6() && ipv6_count < MAX_ADDRS_PER_FAMILY {
                    ipv6_count += 1;
                    true
                } else {
                    false
                }
            })
            .collect()
    }

    fn extract_port_from_hostname(hostname: &str, default: u16) -> u16 {
        hostname
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse::<u16>().ok())
            .unwrap_or(default)
    }

    pub async fn from_config(config: &Config) -> Result<Self, DomainError> {
        Self::new(
            config.dns.pools.clone(),
            None,
            QueryEventEmitter::new_disabled(),
        )
        .await
    }

    pub async fn query(
        &self,
        domain: &Arc<str>,
        record_type: &RecordType,
        timeout_ms: u64,
        dnssec_ok: bool,
    ) -> Result<UpstreamResult, DomainError> {
        debug!(
            total_pools = self.pools.len(),
            %domain, "Starting load balancer query"
        );

        let query_bytes: Arc<[u8]> =
            Arc::from(MessageBuilder::build_query(domain, record_type, dnssec_ok)?);

        for pool in &self.pools {
            let healthy_refs: SmallVec<[&Arc<DnsProtocol>; 16]> =
                if let Some(ref checker) = self.health_checker {
                    pool.server_protocols
                        .iter()
                        .filter(|p| checker.is_healthy(p))
                        .collect()
                } else {
                    pool.server_protocols.iter().collect()
                };

            if healthy_refs.is_empty() {
                debug!(pool = %pool.config.name, "All unhealthy, skipping");
                continue;
            }

            let ctx = QueryContext {
                servers: &healthy_refs,
                domain,
                record_type,
                timeout_ms,
                query_bytes: Arc::clone(&query_bytes),
                emitter: &self.emitter,
                pool_name: &pool.name_arc,
                server_displays: &pool.server_displays,
            };

            match pool.strategy.query_refs(&ctx).await {
                Ok(result) => {
                    debug!(pool = %pool.config.name, server = %result.server, "Pool query successful");
                    return Ok(result);
                }
                Err(e) => {
                    if ResponseParser::is_transport_error(&e) {
                        warn!(pool = %pool.config.name, error = %e, "Transport error, trying next pool");
                        continue;
                    } else {
                        warn!(pool = %pool.config.name, error = %e, "DNS error, not trying other pools");
                        return Err(e);
                    }
                }
            }
        }
        Err(DomainError::TransportAllServersUnreachable)
    }

    pub fn get_all_servers(&self) -> Vec<std::net::SocketAddr> {
        self.pools
            .iter()
            .flat_map(|p| p.server_protocols.iter().filter_map(|p| p.socket_addr()))
            .collect()
    }

    pub fn get_all_arc_protocols(&self) -> Vec<Arc<DnsProtocol>> {
        self.pools
            .iter()
            .flat_map(|p| p.server_protocols.iter().cloned())
            .collect()
    }

    pub fn get_all_protocols(&self) -> Vec<DnsProtocol> {
        self.pools
            .iter()
            .flat_map(|p| p.server_protocols.iter().map(|p| (**p).clone()))
            .collect()
    }
}
