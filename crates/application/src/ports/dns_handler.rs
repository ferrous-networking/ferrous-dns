use async_trait::async_trait;
use ferrous_dns_domain::{dns_request::DnsRequest, DomainError};

#[async_trait]
pub trait DnsHandler: Send + Sync {
    /// Handle DNS query - resolve upstream and check blocklist
    async fn handle_query(
        &self,
        request: &DnsRequest,
    ) -> Result<Vec<IpAddr>, DomainError>;

    /// Check if domain is blocked
    async fn is_blocked(&self, domain: &str) -> Result<bool, DomainError>;
}
