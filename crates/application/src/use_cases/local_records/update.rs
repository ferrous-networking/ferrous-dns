use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use tokio::sync::RwLock;
use tracing::warn;

use crate::ports::{ConfigRepository, PtrRecordRegistry};

pub struct UpdateLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
    ptr_registry: Option<Arc<dyn PtrRecordRegistry>>,
}

impl UpdateLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
            ptr_registry: None,
        }
    }

    /// Attaches a live PTR registry so that a successful record update immediately
    /// swaps the old IP → FQDN mapping for the new one without requiring a server restart.
    pub fn with_ptr_registry(mut self, registry: Option<Arc<dyn PtrRecordRegistry>>) -> Self {
        self.ptr_registry = registry;
        self
    }

    pub async fn execute(
        &self,
        id: i64,
        hostname: String,
        domain: Option<String>,
        ip: String,
        record_type: String,
        ttl: Option<u32>,
    ) -> Result<(LocalDnsRecord, LocalDnsRecord), DomainError> {
        ip.parse::<std::net::IpAddr>()
            .map_err(|_| DomainError::InvalidIpAddress("Invalid IP address".to_string()))?;

        let record_type_upper = record_type.to_uppercase();
        if record_type_upper != "A" && record_type_upper != "AAAA" {
            return Err(DomainError::InvalidDomainName(
                "Invalid record type (must be A or AAAA)".to_string(),
            ));
        }

        let updated_record = LocalDnsRecord {
            hostname,
            domain,
            ip,
            record_type: record_type_upper,
            ttl,
        };

        let mut config = self.config.write().await;

        let idx = id as usize;
        if idx >= config.dns.local_records.len() {
            return Err(DomainError::NotFound(format!(
                "Record with id {} not found",
                id
            )));
        }

        let old_record = config.dns.local_records[idx].clone();
        config.dns.local_records[idx] = updated_record.clone();

        if let Err(e) = self.config_repo.save_local_records(&config).await {
            config.dns.local_records[idx] = old_record;
            return Err(DomainError::IoError(format!(
                "Failed to save configuration: {}",
                e
            )));
        }

        if let Some(ref registry) = self.ptr_registry {
            match old_record.ip.parse() {
                Ok(old_ip) => registry.unregister(old_ip),
                Err(_) => {
                    warn!(ip = %old_record.ip, "PTR registry: failed to parse old IP after update");
                }
            }
            match updated_record.ip.parse() {
                Ok(new_ip) => {
                    let fqdn = updated_record.fqdn(&config.dns.local_domain);
                    registry.register(
                        new_ip,
                        Arc::from(fqdn.as_str()),
                        updated_record.ttl_or_default(),
                    );
                }
                Err(_) => {
                    warn!(ip = %updated_record.ip, "PTR registry: failed to parse new IP after update");
                }
            }
        }

        Ok((updated_record, old_record))
    }
}
