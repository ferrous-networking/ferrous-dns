use super::balanced::BalancedStrategy;
use super::failover::FailoverStrategy;
use super::parallel::ParallelStrategy;
use crate::dns::events::QueryEventEmitter;
use crate::dns::forwarding::DnsResponse;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct UpstreamResult {
    pub response: DnsResponse,
    pub server: SocketAddr,
    pub latency_ms: u64,
}

pub enum Strategy {
    Parallel(ParallelStrategy),
    Balanced(BalancedStrategy),
    Failover(FailoverStrategy),
}

impl Strategy {
    pub async fn query_refs(
        &self,
        servers: &[&DnsProtocol],
        domain: &str,
        record_type: &RecordType,
        timeout_ms: u64,
        emitter: &QueryEventEmitter,
    ) -> Result<UpstreamResult, DomainError> {
        match self {
            Self::Parallel(s) => {
                s.query_refs(servers, domain, record_type, timeout_ms, emitter)
                    .await
            }
            Self::Balanced(s) => {
                s.query_refs(servers, domain, record_type, timeout_ms, emitter)
                    .await
            }
            Self::Failover(s) => {
                s.query_refs(servers, domain, record_type, timeout_ms, emitter)
                    .await
            }
        }
    }
}
