use super::types::DnskeyRecord;
use base64::{engine::general_purpose::STANDARD, Engine};

/// A trust anchor - a trusted DNSKEY for a zone
///
/// Trust anchors are pre-configured DNSKEYs that are trusted without verification.
/// They form the root of trust for DNSSEC validation.
#[derive(Debug, Clone)]
pub struct TrustAnchor {
    /// Domain name (e.g., "." for root)
    pub domain: String,

    /// The trusted DNSKEY
    pub dnskey: DnskeyRecord,

    /// Description (for debugging/logging)
    pub description: String,
}

impl TrustAnchor {
    /// Create a new trust anchor
    pub fn new(domain: String, dnskey: DnskeyRecord, description: String) -> Self {
        Self {
            domain,
            dnskey,
            description,
        }
    }

    /// Check if a DNSKEY matches this trust anchor
    ///
    /// Matches are based on:
    /// - Key tag
    /// - Algorithm
    /// - Public key bytes
    pub fn matches(&self, dnskey: &DnskeyRecord) -> bool {
        // Check key tag
        if self.dnskey.calculate_key_tag() != dnskey.calculate_key_tag() {
            return false;
        }

        // Check algorithm
        if self.dnskey.algorithm != dnskey.algorithm {
            return false;
        }

        // Check public key
        self.dnskey.public_key == dnskey.public_key
    }
}

/// Store for DNSSEC trust anchors
///
/// Manages trust anchors for various zones. By default, includes the
/// root zone KSK.
#[derive(Debug, Clone)]
pub struct TrustAnchorStore {
    anchors: Vec<TrustAnchor>,
}

impl TrustAnchorStore {
    /// Create a new trust anchor store with default root anchors
    pub fn new() -> Self {
        Self {
            anchors: Self::default_root_anchors(),
        }
    }

    /// Create an empty trust anchor store
    pub fn empty() -> Self {
        Self {
            anchors: Vec::new(),
        }
    }

    /// Get default root trust anchors
    ///
    /// ## Current Root KSK (2017)
    ///
    /// - **Key Tag**: 20326
    /// - **Algorithm**: 8 (RSA/SHA-256)
    /// - **Flags**: 257 (KSK with SEP flag)
    /// - **Status**: Active
    ///
    /// ## Trust Anchor Format
    ///
    /// ```text
    /// . 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1v...
    /// ```
    ///
    /// This is the 2017 KSK (KSK-2017) with key tag 20326.
    /// It was introduced during the 2017 root KSK rollover.
    ///
    /// ## Reference
    ///
    /// - IANA: https://www.iana.org/dnssec/files
    /// - RFC 5011: Automated Updates of DNS Security Trust Anchors
    pub fn default_root_anchors() -> Vec<TrustAnchor> {
        vec![
            // Root KSK-2017 (Key Tag: 20326)
            TrustAnchor::new(
                ".".to_string(),
                Self::root_ksk_20326(),
                "Root KSK-2017 (20326)".to_string(),
            ),
        ]
    }

    /// Root KSK-2017 with key tag 20326
    ///
    /// This is the current active root KSK.
    ///
    /// ## Base64-encoded Public Key
    ///
    /// The public key is encoded in base64 as per DNS convention.
    /// When decoded, it contains the RSA public key components.
    fn root_ksk_20326() -> DnskeyRecord {
        // Root KSK-2017 public key (base64)
        // Source: https://www.iana.org/dnssec/files
        let public_key_b64 = concat!(
            "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3",
            "+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kv",
            "ArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF",
            "0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+e",
            "oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfd",
            "RUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwN",
            "R1AkUTV74bU="
        );

        let public_key = STANDARD
            .decode(public_key_b64)
            .expect("Failed to decode root KSK public key");

        DnskeyRecord {
            flags: 257, // KSK flag (256 + SEP flag)
            protocol: 3,
            algorithm: 8, // RSA/SHA-256
            public_key,
        }
    }

    /// Add a custom trust anchor
    pub fn add_anchor(&mut self, anchor: TrustAnchor) {
        self.anchors.push(anchor);
    }

    /// Check if a DNSKEY is trusted for a given domain
    ///
    /// ## Arguments
    ///
    /// - `dnskey`: The DNSKEY to check
    /// - `domain`: The domain name (e.g., "." for root)
    ///
    /// ## Returns
    ///
    /// `true` if the DNSKEY matches a trust anchor for this domain
    pub fn is_trusted(&self, dnskey: &DnskeyRecord, domain: &str) -> bool {
        // Normalize domain (add trailing dot if missing)
        let normalized_domain = if domain.ends_with('.') {
            domain.to_string()
        } else if domain.is_empty() || domain == "." {
            ".".to_string()
        } else {
            format!("{}.", domain)
        };

        self.anchors
            .iter()
            .any(|anchor| anchor.domain == normalized_domain && anchor.matches(dnskey))
    }

    /// Get trust anchor for a domain (if exists)
    pub fn get_anchor(&self, domain: &str) -> Option<&TrustAnchor> {
        let normalized_domain = if domain.ends_with('.') {
            domain.to_string()
        } else {
            format!("{}.", domain)
        };

        self.anchors
            .iter()
            .find(|anchor| anchor.domain == normalized_domain)
    }

    /// Get all trust anchors
    pub fn get_all_anchors(&self) -> &[TrustAnchor] {
        &self.anchors
    }

    /// Load trust anchors from XML file (RFC 7958 format)
    ///
    /// This is for future implementation to support automatic updates.
    /// Currently returns error as not implemented.
    ///
    /// ## Format
    ///
    /// ```xml
    /// <?xml version="1.0" encoding="UTF-8"?>
    /// <TrustAnchor>
    ///   <Zone>.</Zone>
    ///   <KeyDigest id="20326" validFrom="2017-02-02T00:00:00+00:00">
    ///     <KeyTag>20326</KeyTag>
    ///     <Algorithm>8</Algorithm>
    ///     <DigestType>2</DigestType>
    ///     <Digest>E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D</Digest>
    ///   </KeyDigest>
    /// </TrustAnchor>
    /// ```
    #[allow(dead_code)]
    pub fn load_from_xml(&mut self, _xml_content: &str) -> Result<(), String> {
        // Future: Parse XML and add trust anchors
        // For now, just use hardcoded anchors
        Err("XML trust anchor loading not yet implemented".to_string())
    }
}

impl Default for TrustAnchorStore {
    fn default() -> Self {
        Self::new()
    }
}
