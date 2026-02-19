use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    Block,
    Allow,
}

#[async_trait]
pub trait BlockFilterEnginePort: Send + Sync {
    fn resolve_group(&self, ip: IpAddr) -> i64;
    fn check(&self, domain: &str, group_id: i64) -> FilterDecision;
    async fn reload(&self) -> Result<(), DomainError>;
    async fn load_client_groups(&self) -> Result<(), DomainError>;
    fn compiled_domain_count(&self) -> usize;
}
