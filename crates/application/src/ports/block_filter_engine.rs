use async_trait::async_trait;
use ferrous_dns_domain::{BlockSource, DomainError};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterDecision {
    Block(BlockSource),
    Allow,
}

#[async_trait]
pub trait BlockFilterEnginePort: Send + Sync {
    fn resolve_group(&self, ip: IpAddr) -> i64;
    fn check(&self, domain: &str, group_id: i64) -> FilterDecision;
    fn store_cname_decision(&self, domain: &str, group_id: i64, ttl_secs: u64);
    async fn reload(&self) -> Result<(), DomainError>;
    async fn load_client_groups(&self) -> Result<(), DomainError>;
    fn compiled_domain_count(&self) -> usize;
}
