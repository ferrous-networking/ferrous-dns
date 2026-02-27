use super::balanced::BalancedStrategy;
use super::failover::FailoverStrategy;
use super::parallel::ParallelStrategy;
use crate::dns::events::QueryEventEmitter;
use crate::dns::forwarding::DnsResponse;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct UpstreamResult {
    pub response: DnsResponse,
    pub server: SocketAddr,
    pub latency_ms: u64,
    pub pool_name: Arc<str>,
    pub server_display: Arc<str>,
}

pub struct QueryContext<'a> {
    pub servers: &'a [&'a DnsProtocol],
    pub domain: &'a str,
    pub record_type: &'a RecordType,
    pub timeout_ms: u64,
    pub dnssec_ok: bool,
    pub emitter: &'a QueryEventEmitter,
    pub pool_name: &'a Arc<str>,
}

pub enum Strategy {
    Parallel(ParallelStrategy),
    Balanced(BalancedStrategy),
    Failover(FailoverStrategy),
}

impl Strategy {
    pub async fn query_refs(&self, ctx: &QueryContext<'_>) -> Result<UpstreamResult, DomainError> {
        match self {
            Self::Parallel(s) => s.query_refs(ctx).await,
            Self::Balanced(s) => s.query_refs(ctx).await,
            Self::Failover(s) => s.query_refs(ctx).await,
        }
    }
}
