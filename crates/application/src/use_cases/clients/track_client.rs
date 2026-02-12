use crate::ports::ClientRepository;
use ferrous_dns_domain::DomainError;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

/// Use case: Track a client when they make a DNS query
pub struct TrackClientUseCase {
    client_repo: Arc<dyn ClientRepository>,
}

impl TrackClientUseCase {
    pub fn new(client_repo: Arc<dyn ClientRepository>) -> Self {
        Self { client_repo }
    }

    /// Track a client from a DNS request (called from HandleDnsQueryUseCase)
    /// This is fire-and-forget to avoid blocking DNS responses
    pub async fn execute(&self, client_ip: IpAddr) -> Result<(), DomainError> {
        debug!(ip = %client_ip, "Tracking client");

        // Update last_seen and increment query_count
        // This is a simple UPDATE, very fast
        self.client_repo.update_last_seen(client_ip).await?;

        Ok(())
    }
}
