use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]  // ← Added Copy for zero-cost!
pub enum RecordType {
    // Basic records
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    PTR,

    // Advanced records
    SRV,    // Service locator
    SOA,    // Start of Authority
    NS,     // Name Server
    NAPTR,  // Naming Authority Pointer
    DS,     // Delegation Signer (DNSSEC)
    DNSKEY, // DNS Key (DNSSEC)
    SVCB,   // Service Binding
    HTTPS,  // HTTPS Service Binding

    // Security & Modern records (NEW!)
    CAA,   // Certificate Authority Authorization
    TLSA,  // TLS Authentication (DANE)
    SSHFP, // SSH Fingerprint
    DNAME, // Delegation Name

    // DNSSEC records (NEW!)
    RRSIG,      // Resource Record Signature
    NSEC,       // Next Secure
    NSEC3,      // NSEC version 3
    NSEC3PARAM, // NSEC3 Parameters

    // Child DNSSEC (NEW!)
    CDS,     // Child DS
    CDNSKEY, // Child DNSKEY
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
            RecordType::SRV => "SRV",
            RecordType::SOA => "SOA",
            RecordType::NS => "NS",
            RecordType::NAPTR => "NAPTR",
            RecordType::DS => "DS",
            RecordType::DNSKEY => "DNSKEY",
            RecordType::SVCB => "SVCB",
            RecordType::HTTPS => "HTTPS",
            RecordType::CAA => "CAA",
            RecordType::TLSA => "TLSA",
            RecordType::SSHFP => "SSHFP",
            RecordType::DNAME => "DNAME",
            RecordType::RRSIG => "RRSIG",
            RecordType::NSEC => "NSEC",
            RecordType::NSEC3 => "NSEC3",
            RecordType::NSEC3PARAM => "NSEC3PARAM",
            RecordType::CDS => "CDS",
            RecordType::CDNSKEY => "CDNSKEY",
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
            "SRV" => Ok(RecordType::SRV),
            "SOA" => Ok(RecordType::SOA),
            "NS" => Ok(RecordType::NS),
            "NAPTR" => Ok(RecordType::NAPTR),
            "DS" => Ok(RecordType::DS),
            "DNSKEY" => Ok(RecordType::DNSKEY),
            "SVCB" => Ok(RecordType::SVCB),
            "HTTPS" => Ok(RecordType::HTTPS),
            "CAA" => Ok(RecordType::CAA),
            "TLSA" => Ok(RecordType::TLSA),
            "SSHFP" => Ok(RecordType::SSHFP),
            "DNAME" => Ok(RecordType::DNAME),
            "RRSIG" => Ok(RecordType::RRSIG),
            "NSEC" => Ok(RecordType::NSEC),
            "NSEC3" => Ok(RecordType::NSEC3),
            "NSEC3PARAM" => Ok(RecordType::NSEC3PARAM),
            "CDS" => Ok(RecordType::CDS),
            "CDNSKEY" => Ok(RecordType::CDNSKEY),
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
