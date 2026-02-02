use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    PTR,
}

impl RecordType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::TXT => "TXT",
            RecordType::PTR => "PTR",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "A" => Some(RecordType::A),
            "AAAA" => Some(RecordType::AAAA),
            "CNAME" => Some(RecordType::CNAME),
            "MX" => Some(RecordType::MX),
            "TXT" => Some(RecordType::TXT),
            "PTR" => Some(RecordType::PTR),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub domain: String,
    pub record_type: RecordType,
    pub address: IpAddr,  // ← Campo para IP address
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
}
