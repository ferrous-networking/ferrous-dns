use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use tokio::sync::RwLock;
use tracing::warn;

use crate::ports::{ConfigRepository, PtrRecordRegistry};

pub struct DeleteLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
    ptr_registry: Option<Arc<dyn PtrRecordRegistry>>,
}

impl DeleteLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
            ptr_registry: None,
        }
    }

    /// Attaches a live PTR registry so that a successful record deletion immediately
    /// removes the IP → FQDN mapping without requiring a server restart.
    pub fn with_ptr_registry(mut self, registry: Option<Arc<dyn PtrRecordRegistry>>) -> Self {
        self.ptr_registry = registry;
        self
    }

    pub async fn execute(&self, id: i64) -> Result<LocalDnsRecord, DomainError> {
        let mut config = self.config.write().await;

        let idx = id as usize;
        if idx >= config.dns.local_records.len() {
            return Err(DomainError::NotFound(format!(
                "Record with id {} not found",
                id
            )));
        }

        let removed_record = config.dns.local_records.remove(idx);

        if let Err(e) = self.config_repo.save_local_records(&config).await {
            config.dns.local_records.insert(idx, removed_record.clone());
            return Err(DomainError::IoError(format!(
                "Failed to save configuration: {}",
                e
            )));
        }

        if let Some(ref registry) = self.ptr_registry {
            match removed_record.ip.parse() {
                Ok(ip) => registry.unregister(ip),
                Err(_) => {
                    warn!(ip = %removed_record.ip, "PTR registry: failed to parse IP after delete");
                }
            }
        }

        Ok(removed_record)
    }
}
