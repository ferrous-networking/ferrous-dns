use super::RecordType;
use std::net::IpAddr;

/// DNS query request from client (includes client information)
#[derive(Debug, Clone)]
pub struct DnsRequest {
    pub domain: String,
    pub record_type: RecordType,
    pub client_ip: IpAddr,
}

impl DnsRequest {
    pub fn new(domain: String, record_type: RecordType, client_ip: IpAddr) -> Self {
        Self {
            domain,
            record_type,
            client_ip,
        }
    }
}
