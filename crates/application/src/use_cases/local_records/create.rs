use std::sync::Arc;

use ferrous_dns_domain::{Config, DomainError, LocalDnsRecord};
use tokio::sync::RwLock;

use crate::ports::ConfigRepository;

pub struct CreateLocalRecordUseCase {
    config: Arc<RwLock<Config>>,
    config_repo: Arc<dyn ConfigRepository>,
}

impl CreateLocalRecordUseCase {
    pub fn new(config: Arc<RwLock<Config>>, config_repo: Arc<dyn ConfigRepository>) -> Self {
        Self {
            config,
            config_repo,
        }
    }

    pub async fn execute(
        &self,
        hostname: String,
        domain: Option<String>,
        ip: String,
        record_type: String,
        ttl: Option<u32>,
    ) -> Result<(LocalDnsRecord, usize), DomainError> {
        ip.parse::<std::net::IpAddr>()
            .map_err(|_| DomainError::InvalidIpAddress("Invalid IP address".to_string()))?;

        let record_type_upper = record_type.to_uppercase();
        if record_type_upper != "A" && record_type_upper != "AAAA" {
            return Err(DomainError::InvalidDomainName(
                "Invalid record type (must be A or AAAA)".to_string(),
            ));
        }

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

        Ok((new_record, new_index))
    }
}
