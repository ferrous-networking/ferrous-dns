use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord, RecordType};
use tokio::sync::RwLock;
use tracing::warn;

use crate::ports::{ConfigRepository, DnsCachePort, PtrRecordRegistry};

pub struct UpdateLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
    ptr_registry: Option<Arc<dyn PtrRecordRegistry>>,
    dns_cache: Option<Arc<dyn DnsCachePort>>,
}

impl UpdateLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
            ptr_registry: None,
            dns_cache: None,
        }
    }

    /// Attaches a live PTR registry so that a successful record update immediately
    /// swaps the old IP → FQDN mapping for the new one without requiring a server restart.
    pub fn with_ptr_registry(mut self, registry: Option<Arc<dyn PtrRecordRegistry>>) -> Self {
        self.ptr_registry = registry;
        self
    }

    /// Attaches a live DNS cache so that a successful record update immediately
    /// swaps the old forward record (A/AAAA) for the new one without requiring a server restart.
    pub fn with_dns_cache(mut self, cache: Option<Arc<dyn DnsCachePort>>) -> Self {
        self.dns_cache = cache;
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
        let new_parsed_ip = ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| DomainError::InvalidIpAddress("Invalid IP address".to_string()))?;

        let record_type_upper = record_type.to_uppercase();
        let new_parsed_record_type = record_type_upper
            .parse::<RecordType>()
            .ok()
            .filter(|rt| matches!(rt, RecordType::A | RecordType::AAAA))
            .ok_or_else(|| {
                DomainError::InvalidDomainName(
                    "Invalid record type (must be A or AAAA)".to_string(),
                )
            })?;

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

        let old_fqdn = old_record.fqdn(&config.dns.local_domain);
        let new_fqdn = updated_record.fqdn(&config.dns.local_domain);

        if let Some(ref registry) = self.ptr_registry {
            if let Ok(old_ip) = old_record.ip.parse() {
                registry.unregister(old_ip);
            } else {
                warn!(ip = %old_record.ip, "PTR registry: failed to parse old IP after update");
            }
            registry.register(
                new_parsed_ip,
                Arc::from(new_fqdn.as_str()),
                updated_record.ttl_or_default(),
            );
        }

        if let Some(ref cache) = self.dns_cache {
            // old_record.record_type was already validated when first created; parse
            // defensively and skip eviction only if the stored value is somehow invalid.
            if let Ok(old_rt) = old_record.record_type.parse::<RecordType>() {
                cache.remove_record(&old_fqdn, &old_rt);
            } else {
                warn!(
                    record_type = %old_record.record_type,
                    "DNS cache: unrecognised record type on old record, skipping eviction"
                );
            }
            cache.insert_permanent_record(&new_fqdn, new_parsed_record_type, vec![new_parsed_ip]);
        }

        Ok((updated_record, old_record))
    }
}
