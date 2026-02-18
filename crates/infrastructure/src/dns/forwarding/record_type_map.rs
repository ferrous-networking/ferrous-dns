use ferrous_dns_domain::dns_record::{RecordCategory, RecordType};
use hickory_proto::rr::RecordType as HickoryRecordType;
pub struct RecordTypeMapper;

impl RecordTypeMapper {
    
    pub fn to_hickory(record_type: &RecordType) -> HickoryRecordType {
        match record_type {
            
            RecordType::A => HickoryRecordType::A,
            RecordType::AAAA => HickoryRecordType::AAAA,
            RecordType::CNAME => HickoryRecordType::CNAME,
            RecordType::MX => HickoryRecordType::MX,
            RecordType::TXT => HickoryRecordType::TXT,
            RecordType::PTR => HickoryRecordType::PTR,

            RecordType::SRV => HickoryRecordType::SRV,
            RecordType::SOA => HickoryRecordType::SOA,
            RecordType::NS => HickoryRecordType::NS,
            RecordType::NAPTR => HickoryRecordType::NAPTR,
            RecordType::DS => HickoryRecordType::DS,
            RecordType::DNSKEY => HickoryRecordType::DNSKEY,
            RecordType::SVCB => HickoryRecordType::SVCB,
            RecordType::HTTPS => HickoryRecordType::HTTPS,

            RecordType::CAA => HickoryRecordType::CAA,
            RecordType::TLSA => HickoryRecordType::TLSA,
            RecordType::SSHFP => HickoryRecordType::SSHFP,
            RecordType::DNAME => HickoryRecordType::ANAME, 

            RecordType::RRSIG => HickoryRecordType::RRSIG,
            RecordType::NSEC => HickoryRecordType::NSEC,
            RecordType::NSEC3 => HickoryRecordType::NSEC3,
            RecordType::NSEC3PARAM => HickoryRecordType::NSEC3PARAM,

            RecordType::CDS => HickoryRecordType::CDS,
            RecordType::CDNSKEY => HickoryRecordType::CDNSKEY,

            RecordType::OPT => HickoryRecordType::OPT,

            RecordType::NULL => HickoryRecordType::NULL,
            RecordType::HINFO => HickoryRecordType::HINFO,
            
            RecordType::WKS => HickoryRecordType::Unknown(11),

            RecordType::IPSECKEY => HickoryRecordType::Unknown(45),
            RecordType::OPENPGPKEY => HickoryRecordType::OPENPGPKEY,

            RecordType::ZONEMD => HickoryRecordType::Unknown(63),

            RecordType::ANAME => HickoryRecordType::ANAME,
        }
    }

    pub fn from_hickory(hickory_type: HickoryRecordType) -> Option<RecordType> {
        match hickory_type {
            
            HickoryRecordType::A => Some(RecordType::A),
            HickoryRecordType::AAAA => Some(RecordType::AAAA),
            HickoryRecordType::CNAME => Some(RecordType::CNAME),
            HickoryRecordType::MX => Some(RecordType::MX),
            HickoryRecordType::TXT => Some(RecordType::TXT),
            HickoryRecordType::PTR => Some(RecordType::PTR),

            HickoryRecordType::SRV => Some(RecordType::SRV),
            HickoryRecordType::SOA => Some(RecordType::SOA),
            HickoryRecordType::NS => Some(RecordType::NS),
            HickoryRecordType::NAPTR => Some(RecordType::NAPTR),
            HickoryRecordType::DS => Some(RecordType::DS),
            HickoryRecordType::DNSKEY => Some(RecordType::DNSKEY),
            HickoryRecordType::SVCB => Some(RecordType::SVCB),
            HickoryRecordType::HTTPS => Some(RecordType::HTTPS),

            HickoryRecordType::CAA => Some(RecordType::CAA),
            HickoryRecordType::TLSA => Some(RecordType::TLSA),
            HickoryRecordType::SSHFP => Some(RecordType::SSHFP),

            HickoryRecordType::RRSIG => Some(RecordType::RRSIG),
            HickoryRecordType::NSEC => Some(RecordType::NSEC),
            HickoryRecordType::NSEC3 => Some(RecordType::NSEC3),
            HickoryRecordType::NSEC3PARAM => Some(RecordType::NSEC3PARAM),

            HickoryRecordType::CDS => Some(RecordType::CDS),
            HickoryRecordType::CDNSKEY => Some(RecordType::CDNSKEY),

            HickoryRecordType::OPT => Some(RecordType::OPT),

            HickoryRecordType::NULL => Some(RecordType::NULL),
            HickoryRecordType::HINFO => Some(RecordType::HINFO),
            
            HickoryRecordType::Unknown(11) => Some(RecordType::WKS),
            HickoryRecordType::Unknown(45) => Some(RecordType::IPSECKEY),
            HickoryRecordType::Unknown(63) => Some(RecordType::ZONEMD),

            HickoryRecordType::OPENPGPKEY => Some(RecordType::OPENPGPKEY),

            HickoryRecordType::ANAME => Some(RecordType::ANAME),

            _ => None,
        }
    }

    pub fn is_supported(hickory_type: HickoryRecordType) -> bool {
        Self::from_hickory(hickory_type).is_some()
    }

    pub fn hickory_types_for_category(category: RecordCategory) -> Vec<HickoryRecordType> {
        RecordType::by_category(category)
            .into_iter()
            .map(|rt| Self::to_hickory(&rt))
            .collect()
    }

    pub fn is_dnssec(hickory_type: HickoryRecordType) -> bool {
        Self::from_hickory(hickory_type)
            .map(|rt| rt.is_dnssec())
            .unwrap_or(false)
    }

    pub fn is_security_related(hickory_type: HickoryRecordType) -> bool {
        Self::from_hickory(hickory_type)
            .map(|rt| rt.is_security_related())
            .unwrap_or(false)
    }

    pub fn is_modern(hickory_type: HickoryRecordType) -> bool {
        Self::from_hickory(hickory_type)
            .map(|rt| rt.is_modern())
            .unwrap_or(false)
    }
}
