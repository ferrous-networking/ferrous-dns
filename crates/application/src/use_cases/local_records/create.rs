use std::sync::Arc;

use async_trait::async_trait;
use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord, RecordType};
use tokio::sync::RwLock;

use crate::ports::{
    ConfigRepository, DnsCachePort, LocalRecordCreator, PtrRecordRegistry, WildcardRecordRegistry,
};

pub struct CreateLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
    ptr_registry: Option<Arc<dyn PtrRecordRegistry>>,
    dns_cache: Option<Arc<dyn DnsCachePort>>,
    wildcard_registry: Option<Arc<dyn WildcardRecordRegistry>>,
}

impl CreateLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
            ptr_registry: None,
            dns_cache: None,
            wildcard_registry: None,
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

    /// Attaches the live wildcard index so that a newly created wildcard record
    /// answers queries immediately. Wildcards never enter the DNS cache — its
    /// keys are matched exactly, so a `*.example.com` entry there is dead weight.
    pub fn with_wildcard_registry(
        mut self,
        registry: Option<Arc<dyn WildcardRecordRegistry>>,
    ) -> Self {
        self.wildcard_registry = registry;
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
        LocalDnsRecord::validate_hostname(&hostname).map_err(DomainError::InvalidDomainName)?;
        if let Some(ref domain) = domain {
            LocalDnsRecord::validate_domain(domain).map_err(DomainError::InvalidDomainName)?;
        }

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

        if new_record.is_wildcard()
            && new_record
                .wildcard_suffix(&config.dns.local_domain)
                .is_none()
        {
            return Err(DomainError::InvalidDomainName(
                "A wildcard record needs a domain to anchor it: set the domain field or dns.local_domain".to_string(),
            ));
        }

        config.dns.local_records.push(new_record.clone());
        let new_index = config.dns.local_records.len() - 1;

        if let Err(e) = self.config_repo.save_local_records(&config).await {
            config.dns.local_records.pop();
            return Err(DomainError::IoError(format!(
                "Failed to save configuration: {}",
                e
            )));
        }

        if let Some(suffix) = new_record.wildcard_suffix(&config.dns.local_domain) {
            if let Some(ref registry) = self.wildcard_registry {
                registry.register(
                    &suffix,
                    parsed_record_type,
                    parsed_ip,
                    new_record.ttl_or_default(),
                );
            }
            return Ok((new_record, new_index));
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
            cache.insert_permanent_record(
                &fqdn,
                parsed_record_type,
                vec![parsed_ip],
                new_record.ttl_or_default(),
            );
        }

        Ok((new_record, new_index))
    }
}

#[async_trait]
impl LocalRecordCreator for CreateLocalRecordUseCase {
    async fn create_local_record(
        &self,
        hostname: String,
        domain: Option<String>,
        ip: String,
        record_type: String,
        ttl: Option<u32>,
    ) -> Result<LocalDnsRecord, DomainError> {
        self.execute(hostname, domain, ip, record_type, ttl)
            .await
            .map(|(record, _index)| record)
    }
}
