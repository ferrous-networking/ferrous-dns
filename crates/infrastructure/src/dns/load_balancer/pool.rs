use super::balanced::BalancedStrategy;
use super::failover::FailoverStrategy;
use super::health::HealthChecker;
use super::parallel::ParallelStrategy;
use super::strategy::{QueryContext, Strategy, UpstreamResult};
use crate::dns::events::QueryEventEmitter;
use crate::dns::forwarding::ResponseParser;
use crate::dns::transport::resolver;
use ferrous_dns_domain::{
    Config, DnsProtocol, DomainError, RecordType, UpstreamPool, UpstreamStrategy,
};
use smallvec::SmallVec;
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
    server_protocols: Vec<DnsProtocol>,
    name_arc: Arc<str>,
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
            pools_with_strategy.push(PoolWithStrategy {
                config: pool,
                strategy,
                server_protocols: expanded,
                name_arc,
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
                                info!("{} resolved to {} upstream servers", hostname, addrs.len());
                                for addr in &addrs {
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
                                info!("{} pre-resolved to {} addresses", clean_host, addrs.len());
                                for addr in &addrs {
                                    info!("  → {}", addr);
                                }
                                expanded.push(protocol.with_resolved_addrs(addrs));
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
        domain: &str,
        record_type: &RecordType,
        timeout_ms: u64,
        dnssec_ok: bool,
    ) -> Result<UpstreamResult, DomainError> {
        debug!(
            total_pools = self.pools.len(),
            domain, "Starting load balancer query"
        );

        for pool in &self.pools {
            let healthy_refs: SmallVec<[&DnsProtocol; 16]> =
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
                dnssec_ok,
                emitter: &self.emitter,
                pool_name: &pool.name_arc,
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

    pub fn get_all_protocols(&self) -> Vec<DnsProtocol> {
        self.pools
            .iter()
            .flat_map(|p| p.server_protocols.iter().cloned())
            .collect()
    }
}
