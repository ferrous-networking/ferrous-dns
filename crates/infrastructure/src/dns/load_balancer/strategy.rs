use super::{balanced, failover, parallel};
use crate::dns::forwarding::{DnsResponse, ResponseValidator};
use ferrous_dns_domain::{DnsProtocol, DomainError, UpstreamStrategy};
use rustc_hash::FxBuildHasher;
use std::collections::HashMap;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;

/// Display name per configured upstream. Keys are config, not client input,
/// so the non-DoS-resistant Fx hasher is safe here.
pub type ServerDisplays = HashMap<Arc<DnsProtocol>, Arc<str>, FxBuildHasher>;

#[derive(Debug, Clone)]
pub struct UpstreamResult {
    pub response: DnsResponse,
    pub latency_ms: u64,
    pub pool_name: Arc<str>,
    pub server_display: Arc<str>,
    /// The answer came from a conditional pool for an internal zone.
    pub internal: bool,
}

pub struct QueryContext<'a> {
    pub servers: &'a [&'a Arc<DnsProtocol>],
    pub domain: &'a str,
    pub timeout_ms: u64,
    pub query_bytes: &'a [u8],
    pub validator: &'a ResponseValidator,
    pub pool_name: &'a Arc<str>,
    pub server_displays: &'a ServerDisplays,
}

pub enum Strategy {
    Parallel,
    /// Round-robin; `next` picks the server the next query starts from.
    Balanced {
        next: AtomicUsize,
    },
    Failover,
}

impl Strategy {
    pub fn new(strategy: UpstreamStrategy) -> Self {
        match strategy {
            UpstreamStrategy::Parallel => Self::Parallel,
            UpstreamStrategy::Balanced => Self::Balanced {
                next: AtomicUsize::new(0),
            },
            UpstreamStrategy::Failover => Self::Failover,
        }
    }

    pub async fn query_refs(&self, ctx: &QueryContext<'_>) -> Result<UpstreamResult, DomainError> {
        match self {
            Self::Parallel => parallel::query(ctx).await,
            Self::Balanced { next } => balanced::query(ctx, next).await,
            Self::Failover => failover::query(ctx).await,
        }
    }
}
