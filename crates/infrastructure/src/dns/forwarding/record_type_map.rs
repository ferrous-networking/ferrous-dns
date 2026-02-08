use ferrous_dns_domain::dns_record::{RecordCategory, RecordType};
use hickory_proto::rr::RecordType as HickoryRecordType;
pub struct RecordTypeMapper;

impl RecordTypeMapper {
    /// Convert domain RecordType → hickory RecordType (for building queries)
    pub fn to_hickory(record_type: &RecordType) -> HickoryRecordType {
        match record_type {
            // Basic records
            RecordType::A => HickoryRecordType::A,
            RecordType::AAAA => HickoryRecordType::AAAA,
            RecordType::CNAME => HickoryRecordType::CNAME,
            RecordType::MX => HickoryRecordType::MX,
            RecordType::TXT => HickoryRecordType::TXT,
            RecordType::PTR => HickoryRecordType::PTR,

            // Advanced records
            RecordType::SRV => HickoryRecordType::SRV,
            RecordType::SOA => HickoryRecordType::SOA,
            RecordType::NS => HickoryRecordType::NS,
            RecordType::NAPTR => HickoryRecordType::NAPTR,
            RecordType::DS => HickoryRecordType::DS,
            RecordType::DNSKEY => HickoryRecordType::DNSKEY,
            RecordType::SVCB => HickoryRecordType::SVCB,
            RecordType::HTTPS => HickoryRecordType::HTTPS,

            // Security & modern records
            RecordType::CAA => HickoryRecordType::CAA,
            RecordType::TLSA => HickoryRecordType::TLSA,
            RecordType::SSHFP => HickoryRecordType::SSHFP,
            RecordType::DNAME => HickoryRecordType::ANAME, // Hickory maps DNAME → ANAME

            // DNSSEC records
            RecordType::RRSIG => HickoryRecordType::RRSIG,
            RecordType::NSEC => HickoryRecordType::NSEC,
            RecordType::NSEC3 => HickoryRecordType::NSEC3,
            RecordType::NSEC3PARAM => HickoryRecordType::NSEC3PARAM,

            // Child DNSSEC
            RecordType::CDS => HickoryRecordType::CDS,
            RecordType::CDNSKEY => HickoryRecordType::CDNSKEY,

            // EDNS & Protocol Support
            RecordType::OPT => HickoryRecordType::OPT,

            // Legacy/Informational records
            RecordType::NULL => HickoryRecordType::NULL,
            RecordType::HINFO => HickoryRecordType::HINFO,
            // WKS (type 11) not supported by Hickory - use Unknown
            RecordType::WKS => HickoryRecordType::Unknown(11),

            // Security & Cryptography (Extended)
            // IPSECKEY (type 45) not fully supported - use Unknown
            RecordType::IPSECKEY => HickoryRecordType::Unknown(45),
            RecordType::OPENPGPKEY => HickoryRecordType::OPENPGPKEY,

            // Zone Integrity
            // ZONEMD (type 63) not supported by Hickory - use Unknown
            RecordType::ZONEMD => HickoryRecordType::Unknown(63),

            // DNS Alias (ANAME/DNAME mapping)
            RecordType::ANAME => HickoryRecordType::ANAME,
        }
    }

    /// Convert hickory RecordType → domain RecordType (for incoming queries)
    ///
    /// Returns `None` for unsupported record types.
    pub fn from_hickory(hickory_type: HickoryRecordType) -> Option<RecordType> {
        match hickory_type {
            // Basic records
            HickoryRecordType::A => Some(RecordType::A),
            HickoryRecordType::AAAA => Some(RecordType::AAAA),
            HickoryRecordType::CNAME => Some(RecordType::CNAME),
            HickoryRecordType::MX => Some(RecordType::MX),
            HickoryRecordType::TXT => Some(RecordType::TXT),
            HickoryRecordType::PTR => Some(RecordType::PTR),

            // Advanced records
            HickoryRecordType::SRV => Some(RecordType::SRV),
            HickoryRecordType::SOA => Some(RecordType::SOA),
            HickoryRecordType::NS => Some(RecordType::NS),
            HickoryRecordType::NAPTR => Some(RecordType::NAPTR),
            HickoryRecordType::DS => Some(RecordType::DS),
            HickoryRecordType::DNSKEY => Some(RecordType::DNSKEY),
            HickoryRecordType::SVCB => Some(RecordType::SVCB),
            HickoryRecordType::HTTPS => Some(RecordType::HTTPS),

            // Security & modern records
            HickoryRecordType::CAA => Some(RecordType::CAA),
            HickoryRecordType::TLSA => Some(RecordType::TLSA),
            HickoryRecordType::SSHFP => Some(RecordType::SSHFP),

            // DNSSEC records
            HickoryRecordType::RRSIG => Some(RecordType::RRSIG),
            HickoryRecordType::NSEC => Some(RecordType::NSEC),
            HickoryRecordType::NSEC3 => Some(RecordType::NSEC3),
            HickoryRecordType::NSEC3PARAM => Some(RecordType::NSEC3PARAM),

            // Child DNSSEC
            HickoryRecordType::CDS => Some(RecordType::CDS),
            HickoryRecordType::CDNSKEY => Some(RecordType::CDNSKEY),

            // EDNS & Protocol Support
            HickoryRecordType::OPT => Some(RecordType::OPT),

            // Legacy/Informational records
            HickoryRecordType::NULL => Some(RecordType::NULL),
            HickoryRecordType::HINFO => Some(RecordType::HINFO),
            // WKS, IPSECKEY, ZONEMD handled as Unknown types
            HickoryRecordType::Unknown(11) => Some(RecordType::WKS),
            HickoryRecordType::Unknown(45) => Some(RecordType::IPSECKEY),
            HickoryRecordType::Unknown(63) => Some(RecordType::ZONEMD),

            // Security & Cryptography (Extended)
            HickoryRecordType::OPENPGPKEY => Some(RecordType::OPENPGPKEY),

            // DNS Alias - Fixed ANAME/DNAME mapping
            // Hickory uses ANAME internally for both ANAME and DNAME
            HickoryRecordType::ANAME => Some(RecordType::ANAME),

            _ => None,
        }
    }

    /// Validates if a hickory record type is supported
    ///
    /// Centralizes validation logic (DRY principle)
    pub fn is_supported(hickory_type: HickoryRecordType) -> bool {
        Self::from_hickory(hickory_type).is_some()
    }

    /// Returns all hickory types that map to a specific category
    ///
    /// Useful for filtering queries by category
    pub fn hickory_types_for_category(category: RecordCategory) -> Vec<HickoryRecordType> {
        RecordType::by_category(category)
            .into_iter()
            .map(|rt| Self::to_hickory(&rt))
            .collect()
    }

    /// Checks if a hickory type is DNSSEC-related
    pub fn is_dnssec(hickory_type: HickoryRecordType) -> bool {
        Self::from_hickory(hickory_type)
            .map(|rt| rt.is_dnssec())
            .unwrap_or(false)
    }

    /// Checks if a hickory type is security-related
    pub fn is_security_related(hickory_type: HickoryRecordType) -> bool {
        Self::from_hickory(hickory_type)
            .map(|rt| rt.is_security_related())
            .unwrap_or(false)
    }

    /// Checks if a hickory type is modern
    pub fn is_modern(hickory_type: HickoryRecordType) -> bool {
        Self::from_hickory(hickory_type)
            .map(|rt| rt.is_modern())
            .unwrap_or(false)
    }
}
