use super::balanced::BalancedStrategy;
use super::failover::FailoverStrategy;
use super::health::HealthChecker;
use super::parallel::ParallelStrategy;
use super::strategy::{LoadBalancingStrategy, UpstreamResult};
use crate::dns::forwarding::ResponseParser;
use ferrous_dns_domain::{
    Config, DnsProtocol, DomainError, RecordType, UpstreamPool, UpstreamStrategy,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, warn};

pub struct PoolManager {
    pools: Vec<PoolWithStrategy>,
    health_checker: Option<Arc<HealthChecker>>,
}

struct PoolWithStrategy {
    config: UpstreamPool,
    strategy: Box<dyn LoadBalancingStrategy>,
    server_protocols: Vec<DnsProtocol>,
}

impl PoolManager {
    pub fn new(
        pools: Vec<UpstreamPool>,
        health_checker: Option<Arc<HealthChecker>>,
    ) -> Result<Self, DomainError> {
        if pools.is_empty() {
            return Err(DomainError::InvalidDomainName(
                "At least one pool must be configured".into(),
            ));
        }

        let mut pools_with_strategy = Vec::new();
        for pool in pools {
            let strategy: Box<dyn LoadBalancingStrategy> = match pool.strategy {
                UpstreamStrategy::Parallel => Box::new(ParallelStrategy::new()),
                UpstreamStrategy::Balanced => Box::new(BalancedStrategy::new()),
                UpstreamStrategy::Failover => Box::new(FailoverStrategy::new()),
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

            pools_with_strategy.push(PoolWithStrategy {
                config: pool,
                strategy,
                server_protocols: server_protocols?,
            });
        }

        // Pre-sort by priority so query() iterates directly
        pools_with_strategy.sort_by_key(|p| p.config.priority);

        Ok(Self {
            pools: pools_with_strategy,
            health_checker,
        })
    }

    pub fn from_config(config: &Config) -> Result<Self, DomainError> {
        Self::new(config.dns.pools.clone(), None)
    }

    pub async fn query(
        &self,
        domain: &str,
        record_type: &RecordType,
        timeout_ms: u64,
    ) -> Result<UpstreamResult, DomainError> {
        debug!(
            total_pools = self.pools.len(),
            domain, "Starting load balancer query"
        );

        for pool in &self.pools {
            let server_addrs: Vec<SocketAddr> = pool
                .server_protocols
                .iter()
                .filter_map(|p| p.socket_addr())
                .collect();

            let healthy_servers = if let Some(ref checker) = self.health_checker {
                let healthy_addrs = checker.get_healthy_servers(&server_addrs);
                pool.server_protocols
                    .iter()
                    .filter(|p| {
                        p.socket_addr()
                            .map(|a| healthy_addrs.contains(&a))
                            .unwrap_or(true)
                    })
                    .cloned()
                    .collect()
            } else {
                pool.server_protocols.clone()
            };

            if healthy_servers.is_empty() {
                debug!(pool = %pool.config.name, "All unhealthy, skipping");
                continue;
            }

            match pool
                .strategy
                .query(&healthy_servers, domain, record_type, timeout_ms)
                .await
            {
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

        Err(DomainError::InvalidDomainName("All pools exhausted".into()))
    }

    pub fn get_all_servers(&self) -> Vec<SocketAddr> {
        self.pools
            .iter()
            .flat_map(|p| p.server_protocols.iter().filter_map(|p| p.socket_addr()))
            .collect()
    }
}
