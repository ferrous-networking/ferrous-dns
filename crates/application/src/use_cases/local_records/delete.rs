use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord, RecordType};
use tokio::sync::RwLock;
use tracing::warn;

use crate::ports::{ConfigRepository, DnsCachePort, PtrRecordRegistry};

pub struct DeleteLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
    ptr_registry: Option<Arc<dyn PtrRecordRegistry>>,
    dns_cache: Option<Arc<dyn DnsCachePort>>,
}

impl DeleteLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
            ptr_registry: None,
            dns_cache: None,
        }
    }

    /// Attaches a live PTR registry so that a successful record deletion immediately
    /// removes the IP → FQDN mapping without requiring a server restart.
    pub fn with_ptr_registry(mut self, registry: Option<Arc<dyn PtrRecordRegistry>>) -> Self {
        self.ptr_registry = registry;
        self
    }

    /// Attaches a live DNS cache so that a successful record deletion immediately
    /// removes the forward record (A/AAAA) from the cache without requiring a server restart.
    pub fn with_dns_cache(mut self, cache: Option<Arc<dyn DnsCachePort>>) -> Self {
        self.dns_cache = cache;
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

        if let Some(ref cache) = self.dns_cache {
            let fqdn = removed_record.fqdn(&config.dns.local_domain);
            if let Ok(record_type) = removed_record.record_type.parse::<RecordType>() {
                cache.remove_record(&fqdn, &record_type);
            } else {
                warn!(
                    record_type = %removed_record.record_type,
                    "DNS cache: unrecognised record type on removed record, skipping eviction"
                );
            }
        }

        Ok(removed_record)
    }
}
