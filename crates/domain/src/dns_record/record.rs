use super::RecordType;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    
    pub domain: String,
    
    pub record_type: RecordType,
    
    pub address: IpAddr,
    
    pub ttl: u32,
}

impl DnsRecord {
    
    pub fn new(domain: String, record_type: RecordType, address: IpAddr, ttl: u32) -> Self {
        Self {
            domain,
            record_type,
            address,
            ttl,
        }
    }

    pub fn is_expired(&self, elapsed_secs: u32) -> bool {
        elapsed_secs >= self.ttl
    }

    pub fn remaining_ttl(&self, elapsed_secs: u32) -> u32 {
        self.ttl.saturating_sub(elapsed_secs)
    }
}
