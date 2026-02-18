use crate::ports::ClientRepository;
use ferrous_dns_domain::DomainError;
use std::net::IpAddr;
use std::sync::Arc;
use tracing::debug;

pub struct TrackClientUseCase {
    client_repo: Arc<dyn ClientRepository>,
}

impl TrackClientUseCase {
    pub fn new(client_repo: Arc<dyn ClientRepository>) -> Self {
        Self { client_repo }
    }

    pub async fn execute(&self, client_ip: IpAddr) -> Result<(), DomainError> {
        debug!(ip = %client_ip, "Tracking client");

        self.client_repo.update_last_seen(client_ip).await?;

        Ok(())
    }
}
