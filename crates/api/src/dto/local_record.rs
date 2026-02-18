use ferrous_dns_domain::RecordType;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize)]
pub struct LocalRecordDto {
    pub id: i64,
    pub hostname: String,
    pub domain: Option<String>,
    pub fqdn: String,
    pub ip: String,
    pub record_type: String,
    pub ttl: u32,
    pub created_at: Option<String>,
}

impl LocalRecordDto {
    
    pub fn from_config(
        record: &ferrous_dns_domain::LocalDnsRecord,
        index: i64,
        default_domain: &Option<String>,
    ) -> Self {
        let fqdn = record.fqdn(default_domain);

        Self {
            id: index, 
            hostname: record.hostname.clone(),
            domain: record.domain.clone(),
            fqdn,
            ip: record.ip.clone(),
            record_type: record.record_type.clone(),
            ttl: record.ttl.unwrap_or(300),
            created_at: None, 
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateLocalRecordRequest {
    pub hostname: String,
    pub domain: Option<String>,
    pub ip: String,
    pub record_type: String,
    pub ttl: Option<u32>,
}

impl CreateLocalRecordRequest {
    pub fn record_type(&self) -> Option<RecordType> {
        RecordType::from_str(&self.record_type).ok()
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateLocalRecordRequest {
    pub hostname: String,
    pub domain: Option<String>,
    pub ip: String,
    pub record_type: String,
    pub ttl: Option<u32>,
}
