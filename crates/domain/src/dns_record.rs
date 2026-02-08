use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// Categories for DNS record types following Clean Architecture principles (Phase 2)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordCategory {
    /// Basic DNS records (A, AAAA, CNAME, MX, TXT, PTR)
    Basic,
    /// Advanced DNS records (SRV, SOA, NS, NAPTR, SVCB, HTTPS, DNAME, ANAME)
    Advanced,
    /// DNSSEC-related records (DS, DNSKEY, RRSIG, NSEC, NSEC3, etc.)
    Dnssec,
    /// Security and cryptography records (CAA, TLSA, SSHFP, IPSECKEY, OPENPGPKEY)
    Security,
    /// Legacy/informational records (NULL, HINFO, WKS)
    Legacy,
    /// Protocol support (OPT for EDNS0)
    Protocol,
    /// Zone integrity (ZONEMD)
    Integrity,
}

impl RecordCategory {
    /// Returns a human-readable name for the category
    pub fn as_str(&self) -> &'static str {
        match self {
            RecordCategory::Basic => "basic",
            RecordCategory::Advanced => "advanced",
            RecordCategory::Dnssec => "dnssec",
            RecordCategory::Security => "security",
            RecordCategory::Legacy => "legacy",
            RecordCategory::Protocol => "protocol",
            RecordCategory::Integrity => "integrity",
        }
    }

    /// Returns a descriptive label for the category
    pub fn label(&self) -> &'static str {
        match self {
            RecordCategory::Basic => "Basic DNS Records",
            RecordCategory::Advanced => "Advanced DNS Records",
            RecordCategory::Dnssec => "DNSSEC Records",
            RecordCategory::Security => "Security & Cryptography",
            RecordCategory::Legacy => "Legacy Records",
            RecordCategory::Protocol => "Protocol Support",
            RecordCategory::Integrity => "Zone Integrity",
        }
    }
}

impl fmt::Display for RecordCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordType {
    // Basic records
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    PTR,

    // Advanced records
    SRV,
    SOA,
    NS,
    NAPTR,
    DS,
    DNSKEY,
    SVCB,
    HTTPS,

    // Security & Modern records
    CAA,
    TLSA,
    SSHFP,
    DNAME,

    // DNSSEC records
    RRSIG,
    NSEC,
    NSEC3,
    NSEC3PARAM,

    // Child DNSSEC
    CDS,
    CDNSKEY,

    // EDNS & Protocol Support (Phase 1)
    OPT,

    // Legacy/Informational records (Phase 1)
    NULL,
    HINFO,
    WKS,

    // Security & Cryptography (Extended) (Phase 1)
    IPSECKEY,
    OPENPGPKEY,

    // Zone Integrity (Phase 1)
    ZONEMD,

    // DNS Alias (ANAME) (Phase 1)
    ANAME,
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
            RecordType::OPT => "OPT",
            RecordType::NULL => "NULL",
            RecordType::HINFO => "HINFO",
            RecordType::WKS => "WKS",
            RecordType::IPSECKEY => "IPSECKEY",
            RecordType::OPENPGPKEY => "OPENPGPKEY",
            RecordType::ZONEMD => "ZONEMD",
            RecordType::ANAME => "ANAME",
        }
    }

    /// Convert from wire format number (RFC 1035)
    ///
    /// ## Wire Format Numbers
    /// - 1: A
    /// - 2: NS
    /// - 5: CNAME
    /// - 6: SOA
    /// - 28: AAAA
    /// - 43: DS
    /// - 46: RRSIG
    /// - 48: DNSKEY
    /// - etc.
    ///
    /// Returns A for unknown types (safe default)
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => RecordType::A,
            2 => RecordType::NS,
            5 => RecordType::CNAME,
            6 => RecordType::SOA,
            12 => RecordType::PTR,
            15 => RecordType::MX,
            16 => RecordType::TXT,
            28 => RecordType::AAAA,
            33 => RecordType::SRV,
            35 => RecordType::NAPTR,
            39 => RecordType::DNAME,
            41 => RecordType::OPT,
            43 => RecordType::DS,
            44 => RecordType::SSHFP,
            46 => RecordType::RRSIG,
            47 => RecordType::NSEC,
            48 => RecordType::DNSKEY,
            50 => RecordType::NSEC3,
            51 => RecordType::NSEC3PARAM,
            52 => RecordType::TLSA,
            59 => RecordType::CDS,
            60 => RecordType::CDNSKEY,
            64 => RecordType::SVCB,
            65 => RecordType::HTTPS,
            257 => RecordType::CAA,
            _ => RecordType::A, // Default for unknown types
        }
    }

    /// Convert to wire format number
    pub fn to_u16(&self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::NS => 2,
            RecordType::CNAME => 5,
            RecordType::SOA => 6,
            RecordType::PTR => 12,
            RecordType::MX => 15,
            RecordType::TXT => 16,
            RecordType::AAAA => 28,
            RecordType::SRV => 33,
            RecordType::NAPTR => 35,
            RecordType::DNAME => 39,
            RecordType::OPT => 41,
            RecordType::DS => 43,
            RecordType::SSHFP => 44,
            RecordType::RRSIG => 46,
            RecordType::NSEC => 47,
            RecordType::DNSKEY => 48,
            RecordType::NSEC3 => 50,
            RecordType::NSEC3PARAM => 51,
            RecordType::TLSA => 52,
            RecordType::CDS => 59,
            RecordType::CDNSKEY => 60,
            RecordType::SVCB => 64,
            RecordType::HTTPS => 65,
            RecordType::CAA => 257,
            RecordType::NULL => 10,
            RecordType::HINFO => 13,
            RecordType::WKS => 11,
            RecordType::IPSECKEY => 45,
            RecordType::OPENPGPKEY => 61,
            RecordType::ZONEMD => 63,
            RecordType::ANAME => 65401, // Private use range
        }
    }

    /// Returns the category this record type belongs to (Phase 2)
    pub fn category(&self) -> RecordCategory {
        match self {
            RecordType::A
            | RecordType::AAAA
            | RecordType::CNAME
            | RecordType::MX
            | RecordType::TXT
            | RecordType::PTR => RecordCategory::Basic,

            RecordType::SRV
            | RecordType::SOA
            | RecordType::NS
            | RecordType::NAPTR
            | RecordType::SVCB
            | RecordType::HTTPS
            | RecordType::DNAME
            | RecordType::ANAME => RecordCategory::Advanced,

            RecordType::DS
            | RecordType::DNSKEY
            | RecordType::RRSIG
            | RecordType::NSEC
            | RecordType::NSEC3
            | RecordType::NSEC3PARAM
            | RecordType::CDS
            | RecordType::CDNSKEY => RecordCategory::Dnssec,

            RecordType::CAA
            | RecordType::TLSA
            | RecordType::SSHFP
            | RecordType::IPSECKEY
            | RecordType::OPENPGPKEY => RecordCategory::Security,

            RecordType::NULL | RecordType::HINFO | RecordType::WKS => RecordCategory::Legacy,

            RecordType::OPT => RecordCategory::Protocol,

            RecordType::ZONEMD => RecordCategory::Integrity,
        }
    }

    /// Checks if this record type is DNSSEC-related (Phase 2)
    pub fn is_dnssec(&self) -> bool {
        matches!(self.category(), RecordCategory::Dnssec)
    }

    /// Checks if this record type is security-related (including DNSSEC) (Phase 2)
    pub fn is_security_related(&self) -> bool {
        matches!(
            self.category(),
            RecordCategory::Dnssec | RecordCategory::Security | RecordCategory::Integrity
        )
    }

    /// Checks if this record type is commonly used in modern DNS (Phase 2)
    pub fn is_modern(&self) -> bool {
        matches!(
            self,
            RecordType::SVCB
                | RecordType::HTTPS
                | RecordType::CAA
                | RecordType::TLSA
                | RecordType::ANAME
                | RecordType::OPENPGPKEY
                | RecordType::IPSECKEY
                | RecordType::ZONEMD
        )
    }

    /// Checks if this record type is legacy/deprecated (Phase 2)
    pub fn is_legacy(&self) -> bool {
        matches!(self.category(), RecordCategory::Legacy)
    }

    /// Returns all supported record types (Phase 2)
    pub fn all() -> Vec<RecordType> {
        vec![
            RecordType::A,
            RecordType::AAAA,
            RecordType::CNAME,
            RecordType::MX,
            RecordType::TXT,
            RecordType::PTR,
            RecordType::SRV,
            RecordType::SOA,
            RecordType::NS,
            RecordType::NAPTR,
            RecordType::SVCB,
            RecordType::HTTPS,
            RecordType::DNAME,
            RecordType::ANAME,
            RecordType::DS,
            RecordType::DNSKEY,
            RecordType::RRSIG,
            RecordType::NSEC,
            RecordType::NSEC3,
            RecordType::NSEC3PARAM,
            RecordType::CDS,
            RecordType::CDNSKEY,
            RecordType::CAA,
            RecordType::TLSA,
            RecordType::SSHFP,
            RecordType::IPSECKEY,
            RecordType::OPENPGPKEY,
            RecordType::NULL,
            RecordType::HINFO,
            RecordType::WKS,
            RecordType::OPT,
            RecordType::ZONEMD,
        ]
    }

    /// Returns all record types in a specific category (Phase 2)
    pub fn by_category(category: RecordCategory) -> Vec<RecordType> {
        Self::all()
            .into_iter()
            .filter(|rt| rt.category() == category)
            .collect()
    }

    /// Validates if a record type name is supported (Phase 2)
    pub fn is_supported(name: &str) -> bool {
        Self::from_str(name).is_ok()
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

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
            "OPT" => Ok(RecordType::OPT),
            "NULL" => Ok(RecordType::NULL),
            "HINFO" => Ok(RecordType::HINFO),
            "WKS" => Ok(RecordType::WKS),
            "IPSECKEY" => Ok(RecordType::IPSECKEY),
            "OPENPGPKEY" => Ok(RecordType::OPENPGPKEY),
            "ZONEMD" => Ok(RecordType::ZONEMD),
            "ANAME" => Ok(RecordType::ANAME),
            _ => Err(format!("Invalid record type: {}", s)),
        }
    }
}

#[derive(Debug, Clone)]
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
}
