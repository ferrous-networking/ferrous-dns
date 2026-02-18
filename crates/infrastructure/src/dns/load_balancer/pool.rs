use super::balanced::BalancedStrategy;
use super::failover::FailoverStrategy;
use super::health::HealthChecker;
use super::parallel::ParallelStrategy;
use super::strategy::{Strategy, UpstreamResult};
use crate::dns::events::QueryEventEmitter;
use crate::dns::forwarding::ResponseParser;
use ferrous_dns_domain::{
    Config, DnsProtocol, DomainError, RecordType, UpstreamPool, UpstreamStrategy,
};
use smallvec::SmallVec;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{debug, warn};

pub struct PoolManager {
    pools: Vec<PoolWithStrategy>,
    health_checker: Option<Arc<HealthChecker>>,
    emitter: QueryEventEmitter,
}

struct PoolWithStrategy {
    config: UpstreamPool,
    strategy: Strategy,
    server_protocols: Vec<DnsProtocol>,
}

impl PoolManager {
    
    pub fn new(
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

            pools_with_strategy.push(PoolWithStrategy {
                config: pool,
                strategy,
                server_protocols: server_protocols?,
            });
        }
        pools_with_strategy.sort_by_key(|p| p.config.priority);

        Ok(Self {
            pools: pools_with_strategy,
            health_checker,
            emitter,
        })
    }

    pub fn from_config(config: &Config) -> Result<Self, DomainError> {
        
        Self::new(
            config.dns.pools.clone(),
            None,
            QueryEventEmitter::new_disabled(),
        )
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
            
            let healthy_refs: SmallVec<[&DnsProtocol; 8]> =
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

            match pool
                .strategy
                .query_refs(
                    &healthy_refs,
                    domain,
                    record_type,
                    timeout_ms,
                    &self.emitter,
                )
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

    pub fn get_all_protocols(&self) -> Vec<DnsProtocol> {
        self.pools
            .iter()
            .flat_map(|p| p.server_protocols.iter().cloned())
            .collect()
    }
}
