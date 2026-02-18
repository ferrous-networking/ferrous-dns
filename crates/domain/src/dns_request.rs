use super::RecordType;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct DnsRequest {
    pub domain: Arc<str>,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
}

impl DnsRequest {
    pub fn new(domain: impl Into<Arc<str>>, record_type: RecordType, client_ip: IpAddr) -> Self {
        Self {
            domain: domain.into(),
            record_type,
            client_ip,
        }
    }
}
