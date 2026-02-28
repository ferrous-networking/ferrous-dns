use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use tokio::sync::RwLock;

use crate::ports::ConfigRepository;

pub struct UpdateLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
}

impl UpdateLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
        }
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

        Ok((updated_record, old_record))
    }
}
