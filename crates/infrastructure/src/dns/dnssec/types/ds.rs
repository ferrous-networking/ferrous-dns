use super::algorithm_name;
use ferrous_dns_domain::DomainError;
use std::fmt;
use std::sync::Arc;

/// What a parent zone's authenticated denial of a DS RRset proves about the
/// queried child name. Only these outcomes may end or continue a chain walk
/// without a DS: an empty DS answer with no such proof is a downgrade attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DsDenial {
    /// A delegation (NS) without DS, or an NSEC3 opt-out span that may hide
    /// one: everything below is unsigned.
    InsecureDelegation,
    /// The name exists in the parent zone, or is an empty non-terminal there,
    /// without a zone cut: the parent's keys still govern it.
    NotZoneCut,
    /// Neither the name nor anything below it exists.
    Nonexistent,
}

/// An authenticated answer to "is there a DS at this name?".
#[derive(Debug, Clone)]
pub enum DsLookup {
    /// The parent-signed DS RRset, SHA-1 digests dropped (RFC 8624). Empty
    /// when the delegation publishes only SHA-1 digests.
    Present(Arc<[DsRecord]>),
    Absent(DsDenial),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRecord {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl DsRecord {
    pub fn parse(data: &[u8]) -> Result<Self, DomainError> {
        if data.len() < 4 {
            return Err(DomainError::InvalidDnsResponse(
                "DS record too short".into(),
            ));
        }

        let key_tag = u16::from_be_bytes([data[0], data[1]]);
        let algorithm = data[2];
        let digest_type = data[3];
        let digest = data[4..].to_vec();

        Self::validate_digest_length(digest_type, digest.len())?;

        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }

    fn validate_digest_length(digest_type: u8, length: usize) -> Result<(), DomainError> {
        let expected = match digest_type {
            1 => 20,
            2 => 32,
            4 => 48,
            _ => return Ok(()),
        };

        if length != expected {
            return Err(DomainError::InvalidDnsResponse(format!(
                "Invalid digest length for type {}: got {}, expected {}",
                digest_type, length, expected
            )));
        }

        Ok(())
    }

    pub fn digest_type_name(&self) -> &'static str {
        match self.digest_type {
            1 => "SHA-1",
            2 => "SHA-256",
            4 => "SHA-384",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for DsRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DS(tag={}, algo={}, digest={})",
            self.key_tag,
            algorithm_name(self.algorithm),
            self.digest_type_name()
        )
    }
}
