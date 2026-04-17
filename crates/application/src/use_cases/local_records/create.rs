use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord, RecordType};
use tokio::sync::RwLock;

use crate::ports::{ConfigRepository, DnsCachePort, PtrRecordRegistry};

pub struct CreateLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
    ptr_registry: Option<Arc<dyn PtrRecordRegistry>>,
    dns_cache: Option<Arc<dyn DnsCachePort>>,
}

impl CreateLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
            ptr_registry: None,
            dns_cache: None,
        }
    }

    /// Attaches a live PTR registry so that a successful record creation immediately
    /// registers the new IP → FQDN mapping without requiring a server restart.
    pub fn with_ptr_registry(mut self, registry: Option<Arc<dyn PtrRecordRegistry>>) -> Self {
        self.ptr_registry = registry;
        self
    }

    /// Attaches a live DNS cache so that a successful record creation immediately
    /// inserts the forward record (A/AAAA) into the cache without requiring a server restart.
    pub fn with_dns_cache(mut self, cache: Option<Arc<dyn DnsCachePort>>) -> Self {
        self.dns_cache = cache;
        self
    }

    pub async fn execute(
        &self,
        hostname: String,
        domain: Option<String>,
        ip: String,
        record_type: String,
        ttl: Option<u32>,
    ) -> Result<(LocalDnsRecord, usize), DomainError> {
        let parsed_ip = ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| DomainError::InvalidIpAddress("Invalid IP address".to_string()))?;

        let record_type_upper = record_type.to_uppercase();
        let parsed_record_type = record_type_upper
            .parse::<RecordType>()
            .ok()
            .filter(|rt| matches!(rt, RecordType::A | RecordType::AAAA))
            .ok_or_else(|| {
                DomainError::InvalidDomainName(
                    "Invalid record type (must be A or AAAA)".to_string(),
                )
            })?;

        let new_record = LocalDnsRecord {
            hostname,
            domain,
            ip,
            record_type: record_type_upper,
            ttl,
        };

        let mut config = self.config.write().await;
        config.dns.local_records.push(new_record.clone());
        let new_index = config.dns.local_records.len() - 1;

        if let Err(e) = self.config_repo.save_local_records(&config).await {
            config.dns.local_records.pop();
            return Err(DomainError::IoError(format!(
                "Failed to save configuration: {}",
                e
            )));
        }

        let fqdn = new_record.fqdn(&config.dns.local_domain);

        if let Some(ref registry) = self.ptr_registry {
            registry.register(
                parsed_ip,
                Arc::from(fqdn.as_str()),
                new_record.ttl_or_default(),
            );
        }

        if let Some(ref cache) = self.dns_cache {
            cache.insert_permanent_record(&fqdn, parsed_record_type, vec![parsed_ip]);
        }

        Ok((new_record, new_index))
    }
}
