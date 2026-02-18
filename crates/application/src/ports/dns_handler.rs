use async_trait::async_trait;
use ferrous_dns_domain::{dns_request::DnsRequest, DomainError};
use std::net::IpAddr;

#[async_trait]
pub trait DnsHandler: Send + Sync {

    async fn handle_query(
        &self,
        request: &DnsRequest,
    ) -> Result<Vec<IpAddr>, DomainError>;

    async fn is_blocked(&self, domain: &str) -> Result<bool, DomainError>;
}
