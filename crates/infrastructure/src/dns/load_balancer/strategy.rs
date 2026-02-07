use async_trait::async_trait;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use std::net::SocketAddr;

use crate::dns::forwarding::DnsResponse;

#[derive(Debug, Clone)]
pub struct UpstreamResult {
    pub response: DnsResponse,
    pub server: SocketAddr,
    pub latency_ms: u64,
}

#[async_trait]
pub trait LoadBalancingStrategy: Send + Sync {
    async fn query(
        &self,
        servers: &[DnsProtocol],
        domain: &str,
        record_type: &RecordType,
        timeout_ms: u64,
    ) -> Result<UpstreamResult, DomainError>;

    fn name(&self) -> &'static str;
}
