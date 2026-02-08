use super::types::{DnskeyRecord, DsRecord, RrsigRecord};
use ferrous_dns_domain::DomainError;
use ring::signature;
use sha2::{Digest, Sha256, Sha384};
use std::time::{SystemTime, UNIX_EPOCH};

/// Cryptographic signature verifier for DNSSEC
///
/// Provides methods to verify RRSIG signatures and DS hashes using various
/// cryptographic algorithms.
pub struct SignatureVerifier;

impl SignatureVerifier {
    /// Verify an RRSIG signature using a DNSKEY
    ///
    /// ## Algorithm
    ///
    /// 1. Check time validity of signature
    /// 2. Build canonical wire format of RRset
    /// 3. Verify signature using DNSKEY public key
    ///
    /// ## Arguments
    ///
    /// - `rrsig`: The RRSIG record containing the signature
    /// - `dnskey`: The DNSKEY containing the public key
    /// - `rrset`: The resource records that were signed
    ///
    /// ## Returns
    ///
    /// `Ok(true)` if signature is valid, `Ok(false)` if invalid,
    /// `Err` if verification cannot be performed
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// let verifier = SignatureVerifier;
    /// let valid = verifier.verify_rrsig(&rrsig, &dnskey, &rrset)?;
    /// if valid {
    ///     println!("Signature valid!");
    /// }
    /// ```
    pub fn verify_rrsig(
        &self,
        rrsig: &RrsigRecord,
        dnskey: &DnskeyRecord,
        _rrset: &[String], // Simplified for Phase 2
    ) -> Result<bool, DomainError> {
        // 1. Check time validity
        if !self.is_time_valid(rrsig) {
            return Ok(false);
        }

        // 2. Verify key tag matches
        let key_tag = dnskey.calculate_key_tag();
        if key_tag != rrsig.key_tag {
            return Ok(false);
        }

        // 3. Verify algorithm matches
        if dnskey.algorithm != rrsig.algorithm {
            return Ok(false);
        }

        // 4. Build data to verify (canonical wire format)
        let data_to_verify = self.build_rrsig_data(rrsig)?;

        // 5. Verify signature based on algorithm
        match rrsig.algorithm {
            8 => self.verify_rsa_sha256(&data_to_verify, &rrsig.signature, dnskey),
            13 => self.verify_ecdsa_p256(&data_to_verify, &rrsig.signature, dnskey),
            15 => self.verify_ed25519(&data_to_verify, &rrsig.signature, dnskey),
            _ => Err(DomainError::InvalidDnsResponse(format!(
                "Unsupported DNSSEC algorithm: {}",
                rrsig.algorithm
            ))),
        }
    }

    /// Verify a DS record against a DNSKEY
    ///
    /// Verifies that the DS digest matches the hash of the DNSKEY.
    ///
    /// ## Algorithm
    ///
    /// 1. Build DNSKEY wire format with owner name
    /// 2. Hash using specified digest algorithm
    /// 3. Compare with DS digest
    ///
    /// ## Arguments
    ///
    /// - `ds`: The DS record
    /// - `dnskey`: The DNSKEY to verify
    /// - `owner_name`: The domain name (e.g., "google.com")
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// let verifier = SignatureVerifier;
    /// let valid = verifier.verify_ds(&ds, &dnskey, "google.com")?;
    /// ```
    pub fn verify_ds(
        &self,
        ds: &DsRecord,
        dnskey: &DnskeyRecord,
        owner_name: &str,
    ) -> Result<bool, DomainError> {
        // 1. Verify key tag matches
        let key_tag = dnskey.calculate_key_tag();
        if key_tag != ds.key_tag {
            return Ok(false);
        }

        // 2. Verify algorithm matches
        if dnskey.algorithm != ds.algorithm {
            return Ok(false);
        }

        // 3. Build DNSKEY wire format with owner name
        let dnskey_data = self.build_dnskey_data(dnskey, owner_name)?;

        // 4. Hash based on digest type
        let computed_digest = match ds.digest_type {
            2 => {
                // SHA-256
                let mut hasher = Sha256::new();
                hasher.update(&dnskey_data);
                hasher.finalize().to_vec()
            }
            4 => {
                // SHA-384
                let mut hasher = Sha384::new();
                hasher.update(&dnskey_data);
                hasher.finalize().to_vec()
            }
            _ => {
                return Err(DomainError::InvalidDnsResponse(format!(
                    "Unsupported DS digest type: {}",
                    ds.digest_type
                )))
            }
        };

        // 5. Compare digests
        Ok(computed_digest == ds.digest)
    }

    /// Verify RSA/SHA-256 signature (Algorithm 8)
    ///
    /// Most common DNSSEC algorithm. Uses RSA public key cryptography
    /// with SHA-256 hashing.
    fn verify_rsa_sha256(
        &self,
        data: &[u8],
        signature: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        // Parse RSA public key from DNSKEY
        // Format: exponent length (1 or 3 bytes) + exponent + modulus
        if dnskey.public_key.len() < 3 {
            return Err(DomainError::InvalidDnsResponse(
                "RSA public key too short".into(),
            ));
        }

        let (exponent, modulus) = self.parse_rsa_key(&dnskey.public_key)?;

        // Create RSA public key components
        let public_key = signature::RsaPublicKeyComponents {
            n: &modulus,
            e: &exponent,
        };

        // Verify signature
        match public_key.verify(&signature::RSA_PKCS1_2048_8192_SHA256, data, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false), // Invalid signature, not an error
        }
    }

    /// Verify ECDSA P-256/SHA-256 signature (Algorithm 13)
    ///
    /// Modern algorithm using elliptic curve cryptography.
    /// More efficient than RSA with similar security.
    fn verify_ecdsa_p256(
        &self,
        data: &[u8],
        signature: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        // ECDSA P-256 public key is 64 bytes (32 bytes X + 32 bytes Y)
        if dnskey.public_key.len() != 64 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid ECDSA P-256 public key length".into(),
            ));
        }

        // ECDSA signature is 64 bytes (32 bytes R + 32 bytes S)
        if signature.len() != 64 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid ECDSA P-256 signature length".into(),
            ));
        }

        // Create public key
        let public_key = signature::UnparsedPublicKey::new(
            &signature::ECDSA_P256_SHA256_ASN1,
            &dnskey.public_key,
        );

        // Verify signature
        match public_key.verify(data, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify Ed25519 signature (Algorithm 15)
    ///
    /// Modern algorithm using Edwards-curve Digital Signature Algorithm.
    /// Fast and secure.
    fn verify_ed25519(
        &self,
        data: &[u8],
        signature: &[u8],
        dnskey: &DnskeyRecord,
    ) -> Result<bool, DomainError> {
        // Ed25519 public key is 32 bytes
        if dnskey.public_key.len() != 32 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid Ed25519 public key length".into(),
            ));
        }

        // Ed25519 signature is 64 bytes
        if signature.len() != 64 {
            return Err(DomainError::InvalidDnsResponse(
                "Invalid Ed25519 signature length".into(),
            ));
        }

        // Create public key
        let public_key = signature::UnparsedPublicKey::new(&signature::ED25519, &dnskey.public_key);

        // Verify signature
        match public_key.verify(data, signature) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Parse RSA public key from DNSKEY format
    ///
    /// ## Format
    /// - If exponent length fits in 1 byte:
    ///   - 1 byte: exponent length
    ///   - N bytes: exponent
    ///   - Remaining: modulus
    /// - If exponent length needs 3 bytes:
    ///   - 1 byte: 0x00
    ///   - 2 bytes: exponent length
    ///   - N bytes: exponent
    ///   - Remaining: modulus
    fn parse_rsa_key(&self, key_data: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DomainError> {
        if key_data.is_empty() {
            return Err(DomainError::InvalidDnsResponse(
                "Empty RSA public key".into(),
            ));
        }

        let first_byte = key_data[0];

        let (exp_len, exp_start) = if first_byte == 0 {
            // Long form: 3 bytes for length
            if key_data.len() < 3 {
                return Err(DomainError::InvalidDnsResponse(
                    "RSA key too short for long form".into(),
                ));
            }
            let exp_len = u16::from_be_bytes([key_data[1], key_data[2]]) as usize;
            (exp_len, 3)
        } else {
            // Short form: 1 byte for length
            (first_byte as usize, 1)
        };

        let exp_end = exp_start + exp_len;
        if exp_end > key_data.len() {
            return Err(DomainError::InvalidDnsResponse(
                "RSA exponent extends beyond key data".into(),
            ));
        }

        let exponent = key_data[exp_start..exp_end].to_vec();
        let modulus = key_data[exp_end..].to_vec();

        if modulus.is_empty() {
            return Err(DomainError::InvalidDnsResponse(
                "RSA modulus is empty".into(),
            ));
        }

        Ok((exponent, modulus))
    }

    /// Build RRSIG data for verification (canonical wire format)
    ///
    /// ## Format (RFC 4034 Section 3.1.8.1)
    /// ```text
    /// RRSIG_RDATA (without signature) + RRset (canonical order)
    /// ```
    fn build_rrsig_data(&self, rrsig: &RrsigRecord) -> Result<Vec<u8>, DomainError> {
        let mut data = Vec::new();

        // RRSIG RDATA (without signature)
        data.extend_from_slice(&rrsig.type_covered.to_u16().to_be_bytes());
        data.push(rrsig.algorithm);
        data.push(rrsig.labels);
        data.extend_from_slice(&rrsig.original_ttl.to_be_bytes());
        data.extend_from_slice(&rrsig.signature_expiration.to_be_bytes());
        data.extend_from_slice(&rrsig.signature_inception.to_be_bytes());
        data.extend_from_slice(&rrsig.key_tag.to_be_bytes());

        // Signer name (DNS wire format)
        let signer_wire = self.name_to_wire(&rrsig.signer_name)?;
        data.extend_from_slice(&signer_wire);

        // Note: In a complete implementation, we would add the
        // canonical RRset here. For Phase 2, we're verifying the
        // signature structure but not the complete RRset.

        Ok(data)
    }

    /// Build DNSKEY data for DS hash calculation
    ///
    /// ## Format (RFC 4034 Section 5.1.4)
    /// ```text
    /// owner name (wire format) + DNSKEY RDATA
    /// ```
    fn build_dnskey_data(
        &self,
        dnskey: &DnskeyRecord,
        owner_name: &str,
    ) -> Result<Vec<u8>, DomainError> {
        let mut data = Vec::new();

        // Owner name in wire format
        let name_wire = self.name_to_wire(owner_name)?;
        data.extend_from_slice(&name_wire);

        // DNSKEY RDATA
        data.extend_from_slice(&dnskey.flags.to_be_bytes());
        data.push(dnskey.protocol);
        data.push(dnskey.algorithm);
        data.extend_from_slice(&dnskey.public_key);

        Ok(data)
    }

    /// Convert DNS name to wire format
    ///
    /// ## Format
    /// ```text
    /// example.com. → 0x07 e x a m p l e 0x03 c o m 0x00
    /// ```
    fn name_to_wire(&self, name: &str) -> Result<Vec<u8>, DomainError> {
        let mut wire = Vec::new();

        // Remove trailing dot if present
        let name = name.trim_end_matches('.');

        if name.is_empty() || name == "." {
            // Root
            wire.push(0);
            return Ok(wire);
        }

        // Split into labels
        for label in name.split('.') {
            if label.is_empty() {
                return Err(DomainError::InvalidDnsResponse("Empty DNS label".into()));
            }

            if label.len() > 63 {
                return Err(DomainError::InvalidDnsResponse("DNS label too long".into()));
            }

            // Label length
            wire.push(label.len() as u8);

            // Label content (lowercase for canonical form)
            wire.extend_from_slice(label.to_lowercase().as_bytes());
        }

        // Root label
        wire.push(0);

        Ok(wire)
    }

    /// Check if RRSIG is time-valid
    fn is_time_valid(&self, rrsig: &RrsigRecord) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0);

        now >= rrsig.signature_inception && now <= rrsig.signature_expiration
    }
}
