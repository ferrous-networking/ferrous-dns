use ferrous_dns_domain::{DomainError, RecordType};
use std::fmt;

/// DNSKEY Record - Public key for DNSSEC
///
/// Contains the public key used to verify RRSIG signatures.
///
/// ## Wire Format
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Flags                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Protocol (must be 3)                |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Algorithm                           |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Public Key (variable length)        |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// ## Flags
/// - Bit 7: Zone Key flag (must be 1)
/// - Bit 15: Secure Entry Point (SEP) flag (1 for KSK, 0 for ZSK)
///
/// ## Algorithms
/// - 8: RSA/SHA-256
/// - 13: ECDSA P-256/SHA-256
/// - 15: Ed25519
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnskeyRecord {
    /// Flags field (16 bits)
    /// - 256 (0x0100): Zone Signing Key (ZSK)
    /// - 257 (0x0101): Key Signing Key (KSK) with SEP flag
    pub flags: u16,

    /// Protocol field (must be 3 for DNSSEC)
    pub protocol: u8,

    /// Algorithm number
    /// - 8: RSA/SHA-256
    /// - 13: ECDSA P-256/SHA-256
    /// - 15: Ed25519
    pub algorithm: u8,

    /// Public key bytes
    pub public_key: Vec<u8>,
}

impl DnskeyRecord {
    /// Parse DNSKEY from wire format
    ///
    /// ## Format
    /// - 2 bytes: flags
    /// - 1 byte: protocol
    /// - 1 byte: algorithm
    /// - N bytes: public key
    pub fn parse(data: &[u8]) -> Result<Self, DomainError> {
        if data.len() < 4 {
            return Err(DomainError::InvalidDnsResponse(
                "DNSKEY record too short".into(),
            ));
        }

        let flags = u16::from_be_bytes([data[0], data[1]]);
        let protocol = data[2];
        let algorithm = data[3];
        let public_key = data[4..].to_vec();

        // Validate protocol (must be 3)
        if protocol != 3 {
            return Err(DomainError::InvalidDnsResponse(format!(
                "Invalid DNSKEY protocol: {} (expected 3)",
                protocol
            )));
        }

        // Validate Zone Key flag (bit 7 must be 1)
        if flags & 0x0100 == 0 {
            return Err(DomainError::InvalidDnsResponse(
                "DNSKEY Zone Key flag not set".into(),
            ));
        }

        Ok(Self {
            flags,
            protocol,
            algorithm,
            public_key,
        })
    }

    /// Check if this is a Key Signing Key (KSK)
    ///
    /// KSKs have the SEP (Secure Entry Point) flag set (bit 15).
    pub fn is_ksk(&self) -> bool {
        self.flags & 0x0001 != 0 // SEP flag
    }

    /// Check if this is a Zone Signing Key (ZSK)
    pub fn is_zsk(&self) -> bool {
        !self.is_ksk()
    }

    /// Calculate the key tag (RFC 4034 Appendix B)
    ///
    /// The key tag is a 16-bit identifier used to efficiently select
    /// the correct DNSKEY when verifying an RRSIG.
    ///
    /// ## Algorithm
    /// 1. Initialize accumulator to 0
    /// 2. For each byte pair in wire format:
    ///    - Add to accumulator
    /// 3. Add overflow to lower 16 bits
    /// 4. Return lower 16 bits
    pub fn calculate_key_tag(&self) -> u16 {
        let mut wire = Vec::with_capacity(4 + self.public_key.len());
        wire.extend_from_slice(&self.flags.to_be_bytes());
        wire.push(self.protocol);
        wire.push(self.algorithm);
        wire.extend_from_slice(&self.public_key);

        let mut accumulator: u32 = 0;

        // Process pairs of bytes
        for chunk in wire.chunks(2) {
            if chunk.len() == 2 {
                accumulator += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
            } else {
                // Odd byte at end (left-shifted)
                accumulator += u32::from(chunk[0]) << 8;
            }
        }

        // Add overflow
        accumulator += accumulator >> 16;

        // Return lower 16 bits
        (accumulator & 0xFFFF) as u16
    }

    /// Get algorithm name
    pub fn algorithm_name(&self) -> &'static str {
        match self.algorithm {
            8 => "RSA/SHA-256",
            13 => "ECDSA P-256/SHA-256",
            15 => "Ed25519",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for DnskeyRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNSKEY(flags={}, algo={}, tag={}, {})",
            self.flags,
            self.algorithm_name(),
            self.calculate_key_tag(),
            if self.is_ksk() { "KSK" } else { "ZSK" }
        )
    }
}

/// DS Record - Delegation Signer
///
/// Links parent zone to child zone by containing a hash of the child's DNSKEY.
/// This forms the chain of trust in DNSSEC.
///
/// ## Wire Format
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Key Tag                             |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Algorithm                           |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Digest Type                         |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Digest (variable length)            |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
///
/// ## Digest Types
/// - 1: SHA-1 (deprecated)
/// - 2: SHA-256 (recommended)
/// - 4: SHA-384
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DsRecord {
    /// Key tag of the DNSKEY this DS refers to
    pub key_tag: u16,

    /// Algorithm of the DNSKEY
    pub algorithm: u8,

    /// Digest type
    /// - 1: SHA-1 (deprecated)
    /// - 2: SHA-256
    /// - 4: SHA-384
    pub digest_type: u8,

    /// Digest (hash) of the DNSKEY
    pub digest: Vec<u8>,
}

impl DsRecord {
    /// Parse DS from wire format
    ///
    /// ## Format
    /// - 2 bytes: key tag
    /// - 1 byte: algorithm
    /// - 1 byte: digest type
    /// - N bytes: digest
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

        // Validate digest length based on type
        let expected_len = match digest_type {
            1 => 20, // SHA-1
            2 => 32, // SHA-256
            4 => 48, // SHA-384
            _ => 0,  // Unknown, allow any length
        };

        if expected_len > 0 && digest.len() != expected_len {
            return Err(DomainError::InvalidDnsResponse(format!(
                "Invalid DS digest length: {} (expected {})",
                digest.len(),
                expected_len
            )));
        }

        Ok(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        })
    }

    /// Get digest type name
    pub fn digest_type_name(&self) -> &'static str {
        match self.digest_type {
            1 => "SHA-1",
            2 => "SHA-256",
            4 => "SHA-384",
            _ => "Unknown",
        }
    }

    /// Get algorithm name
    pub fn algorithm_name(&self) -> &'static str {
        match self.algorithm {
            8 => "RSA/SHA-256",
            13 => "ECDSA P-256/SHA-256",
            15 => "Ed25519",
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
            self.algorithm_name(),
            self.digest_type_name()
        )
    }
}

/// RRSIG Record - Resource Record Signature
///
/// Contains the cryptographic signature of an RRset, signed by a DNSKEY.
///
/// ## Wire Format
/// ```text
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Type Covered                        |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Algorithm                           |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Labels                              |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Original TTL                        |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Signature Expiration                |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Signature Inception                 |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Key Tag                             |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Signer's Name (variable)            |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |           Signature (variable)                |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RrsigRecord {
    /// Type of RRset covered by this signature
    pub type_covered: RecordType,

    /// Algorithm used for signature
    pub algorithm: u8,

    /// Number of labels in original owner name
    pub labels: u8,

    /// Original TTL of the RRset
    pub original_ttl: u32,

    /// Signature expiration time (Unix timestamp)
    pub signature_expiration: u32,

    /// Signature inception time (Unix timestamp)
    pub signature_inception: u32,

    /// Key tag of DNSKEY used to sign
    pub key_tag: u16,

    /// Name of the signer (zone name)
    pub signer_name: String,

    /// Cryptographic signature
    pub signature: Vec<u8>,
}

impl RrsigRecord {
    /// Parse RRSIG from wire format
    ///
    /// ## Format (fixed part)
    /// - 2 bytes: type covered
    /// - 1 byte: algorithm
    /// - 1 byte: labels
    /// - 4 bytes: original TTL
    /// - 4 bytes: signature expiration
    /// - 4 bytes: signature inception
    /// - 2 bytes: key tag
    /// - Variable: signer name (DNS name format)
    /// - Variable: signature
    pub fn parse(data: &[u8]) -> Result<Self, DomainError> {
        if data.len() < 18 {
            return Err(DomainError::InvalidDnsResponse(
                "RRSIG record too short".into(),
            ));
        }

        let type_covered_num = u16::from_be_bytes([data[0], data[1]]);
        let type_covered = RecordType::from_u16(type_covered_num);

        let algorithm = data[2];
        let labels = data[3];
        let original_ttl = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let signature_expiration = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let signature_inception = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
        let key_tag = u16::from_be_bytes([data[16], data[17]]);

        // Parse signer name (DNS name format)
        let (signer_name, name_len) = Self::parse_dns_name(&data[18..])?;

        // Remaining bytes are the signature
        let signature_start = 18 + name_len;
        if signature_start >= data.len() {
            return Err(DomainError::InvalidDnsResponse(
                "RRSIG missing signature".into(),
            ));
        }

        let signature = data[signature_start..].to_vec();

        Ok(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        })
    }

    /// Parse DNS name from wire format
    ///
    /// Returns (name, bytes_consumed)
    fn parse_dns_name(data: &[u8]) -> Result<(String, usize), DomainError> {
        let mut labels = Vec::new();
        let mut pos = 0;

        loop {
            if pos >= data.len() {
                return Err(DomainError::InvalidDnsResponse("DNS name truncated".into()));
            }

            let len = data[pos] as usize;
            pos += 1;

            if len == 0 {
                // Root label (end of name)
                break;
            }

            if len > 63 {
                return Err(DomainError::InvalidDnsResponse(
                    "Invalid DNS label length".into(),
                ));
            }

            if pos + len > data.len() {
                return Err(DomainError::InvalidDnsResponse(
                    "DNS label truncated".into(),
                ));
            }

            let label = String::from_utf8_lossy(&data[pos..pos + len]).to_string();
            labels.push(label);
            pos += len;
        }

        let name = if labels.is_empty() {
            ".".to_string()
        } else {
            format!("{}.", labels.join("."))
        };

        Ok((name, pos))
    }

    /// Check if signature is currently valid (time-wise)
    pub fn is_time_valid(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        now >= self.signature_inception && now <= self.signature_expiration
    }

    /// Get algorithm name
    pub fn algorithm_name(&self) -> &'static str {
        match self.algorithm {
            8 => "RSA/SHA-256",
            13 => "ECDSA P-256/SHA-256",
            15 => "Ed25519",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for RrsigRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RRSIG({:?}, algo={}, tag={}, signer={})",
            self.type_covered,
            self.algorithm_name(),
            self.key_tag,
            self.signer_name
        )
    }
}
