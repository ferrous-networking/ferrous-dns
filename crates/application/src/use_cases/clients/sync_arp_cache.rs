use crate::ports::{ArpReader, ClientRepository};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{debug, info};

pub struct SyncArpCacheUseCase {
    arp_reader: Arc<dyn ArpReader>,
    client_repo: Arc<dyn ClientRepository>,
}

impl SyncArpCacheUseCase {
    pub fn new(arp_reader: Arc<dyn ArpReader>, client_repo: Arc<dyn ClientRepository>) -> Self {
        Self {
            arp_reader,
            client_repo,
        }
    }

    pub async fn execute(&self) -> Result<u64, DomainError> {
        debug!("Reading ARP cache");

        let arp_table = self.arp_reader.read_arp_table().await?;
        let count = arp_table.len();

        debug!(entries = count, "ARP table read successfully");

        let updates: Vec<_> = arp_table.into_iter().collect();

        let updated = self.client_repo.batch_update_mac_addresses(updates).await?;

        info!(total = count, updated, "ARP cache synchronized");
        Ok(updated)
    }
}
