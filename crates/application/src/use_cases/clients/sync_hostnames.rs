use crate::ports::{ClientRepository, HostnameResolver};
use ferrous_dns_domain::DomainError;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub struct SyncHostnamesUseCase {
    client_repo: Arc<dyn ClientRepository>,
    hostname_resolver: Arc<dyn HostnameResolver>,
}

impl SyncHostnamesUseCase {
    pub fn new(
        client_repo: Arc<dyn ClientRepository>,
        hostname_resolver: Arc<dyn HostnameResolver>,
    ) -> Self {
        Self {
            client_repo,
            hostname_resolver,
        }
    }

    pub async fn execute(&self, batch_size: u32) -> Result<u64, DomainError> {
        debug!(batch_size, "Resolving hostnames for clients");

        let clients = self
            .client_repo
            .get_needs_hostname_update(batch_size)
            .await?;
        let mut resolved = 0u64;

        for client in clients {
            match self
                .hostname_resolver
                .resolve_hostname(client.ip_address)
                .await
            {
                Ok(Some(hostname)) => {
                    match self
                        .client_repo
                        .update_hostname(client.ip_address, hostname)
                        .await
                    {
                        Ok(_) => resolved += 1,
                        Err(e) => {
                            warn!(error = %e, ip = %client.ip_address, "Failed to update hostname")
                        }
                    }
                }
                Ok(None) => {
                    debug!(ip = %client.ip_address, "No PTR record found");
                }
                Err(e) => {
                    warn!(error = %e, ip = %client.ip_address, "Hostname resolution failed");
                }
            }
        }

        info!(resolved, "Hostnames synchronized");
        Ok(resolved)
    }
}
