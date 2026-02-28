use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use tokio::sync::RwLock;

use crate::ports::ConfigRepository;

pub struct DeleteLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
}

impl DeleteLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
        }
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

        Ok(removed_record)
    }
}
