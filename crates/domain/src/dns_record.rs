use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

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
}

// Implement Display trait for easy string conversion
impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

// Implement FromStr trait (standard Rust way)
impl FromStr for RecordType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CNAME" => Ok(RecordType::CNAME),
            "MX" => Ok(RecordType::MX),
            "TXT" => Ok(RecordType::TXT),
            "PTR" => Ok(RecordType::PTR),
            _ => Err(format!("Invalid record type: {}", s)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub domain: String,
    pub record_type: RecordType,
    pub address: IpAddr, // ← Campo para IP address
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
