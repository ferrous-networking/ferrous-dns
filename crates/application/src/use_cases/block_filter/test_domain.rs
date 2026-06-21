use crate::ports::BlockFilterEnginePort;
use ferrous_dns_domain::FilterExplanation;
use std::net::IpAddr;
use std::sync::Arc;

/// Explains how the static filter index evaluates a single domain.
pub struct TestDomainUseCase {
    engine: Arc<dyn BlockFilterEnginePort>,
}

impl TestDomainUseCase {
    pub fn new(engine: Arc<dyn BlockFilterEnginePort>) -> Self {
        Self { engine }
    }

    /// Evaluate `domain`. Group resolution precedence: an explicit `group_id`
    /// wins; otherwise a valid `client` IP is resolved to its group; otherwise
    /// the default group (1) is used.
    pub fn execute(
        &self,
        domain: &str,
        client: Option<IpAddr>,
        group_id: Option<i64>,
    ) -> FilterExplanation {
        let resolved = group_id
            .or_else(|| client.map(|ip| self.engine.resolve_group(ip)))
            .unwrap_or(1);
        self.engine.explain(domain, resolved)
    }
}
