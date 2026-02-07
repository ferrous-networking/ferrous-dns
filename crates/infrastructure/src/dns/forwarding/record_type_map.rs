//! Centralized mapping between `ferrous_dns_domain::RecordType` and `hickory_proto::rr::RecordType`
//!
//! Previously this conversion was duplicated in:
//! - `resolver.rs` (domain → hickory, 24 match arms)
//! - `server.rs` (hickory → domain, 24 match arms)
//!
//! Now it lives in one place.

use ferrous_dns_domain::RecordType;
use hickory_proto::rr::RecordType as HickoryRecordType;

/// Bidirectional mapper between domain and hickory record types
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

            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_all_types() {
        let types = vec![
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
            RecordType::DS,
            RecordType::DNSKEY,
            RecordType::SVCB,
            RecordType::HTTPS,
            RecordType::CAA,
            RecordType::TLSA,
            RecordType::SSHFP,
            RecordType::RRSIG,
            RecordType::NSEC,
            RecordType::NSEC3,
            RecordType::NSEC3PARAM,
            RecordType::CDS,
            RecordType::CDNSKEY,
        ];

        for rt in types {
            let hickory = RecordTypeMapper::to_hickory(&rt);
            let back = RecordTypeMapper::from_hickory(hickory);
            assert!(
                back.is_some(),
                "Roundtrip failed for {:?} → {:?}",
                rt,
                hickory
            );
        }
    }

    #[test]
    fn test_unsupported_type_returns_none() {
        // ANY is not in our domain model
        let result = RecordTypeMapper::from_hickory(HickoryRecordType::ANY);
        assert!(result.is_none());
    }

    #[test]
    fn test_a_record_mapping() {
        assert_eq!(
            RecordTypeMapper::to_hickory(&RecordType::A),
            HickoryRecordType::A
        );
        assert_eq!(
            RecordTypeMapper::from_hickory(HickoryRecordType::A),
            Some(RecordType::A)
        );
    }
}
