use super::types::{DnskeyRecord, DsRecord};
use ferrous_dns_domain::DomainError;
use hickory_proto::dnssec::rdata::RRSIG;
use hickory_proto::dnssec::TBS;
use hickory_proto::rr::{DNSClass, Name, Record};
use ring::signature;
use sha1::{Digest, Sha1};
use sha2::{Sha256, Sha384};
use std::borrow::Borrow;

/// Whether `rrsig` is a valid signature, by one of `keys`, over `records` — the
/// RRset owned by `owner`.
///
/// Keys are matched on algorithm and key tag first; the to-be-signed data is
/// serialized once, and only when a key matches. A verification error (for
/// example an unsupported algorithm) is returned only if no candidate verifies.
pub fn rrsig_verifies<'r, K: Borrow<DnskeyRecord>>(
    rrsig: &RRSIG,
    keys: &[K],
    owner: &Name,
    records: impl Iterator<Item = &'r Record>,
    now_secs: u32,
) -> Result<bool, DomainError> {
    let input = rrsig.input();
    if !within_validity(
        input.sig_inception.get(),
        input.sig_expiration.get(),
        now_secs,
    ) {
        return Ok(false);
    }

    let algorithm = u8::from(input.algorithm);
    let mut candidates = keys
        .iter()
        .map(Borrow::borrow)
        .filter(|key: &&DnskeyRecord| {
            key.algorithm == algorithm && key.calculate_key_tag() == input.key_tag
        })
        .peekable();
    if candidates.peek().is_none() {
        return Ok(false);
    }

    let tbs = TBS::from_input(owner, DNSClass::IN, input, records)
        .map_err(|e| DomainError::InvalidDnsResponse(e.to_string()))?;
    let mut outcome = Ok(false);
    for key in candidates {
        match verify_signature(algorithm, tbs.as_ref(), rrsig.sig(), key) {
            Ok(true) => return Ok(true),
            Ok(false) => {}
            Err(e) => outcome = Err(e),
        }
    }
    outcome
}

/// RFC 4034 §3.1.5: RRSIG inception/expiration are mod-2^32 serial numbers,
/// not absolute u32s, so a window straddling the 2106 wrap (or a clock near it)
/// must be compared with serial arithmetic. For any window shorter than 2^31
/// seconds (~68 years) this matches the naive comparison.
fn within_validity(inception: u32, expiration: u32, now: u32) -> bool {
    serial_le(inception, now) && serial_le(now, expiration)
}

/// RFC 1982 serial-number `a <= b` in mod-2^32 arithmetic: `b - a` (wrapping)
/// lands in the lower half of the space iff `a` is at or before `b`.
fn serial_le(a: u32, b: u32) -> bool {
    b.wrapping_sub(a) < 0x8000_0000
}

fn verify_signature(
    algorithm: u8,
    data: &[u8],
    sig: &[u8],
    dnskey: &DnskeyRecord,
) -> Result<bool, DomainError> {
    // 1024-bit RSA ZSKs are still common in deployed DNSSEC zones (RFC 8624
    // discourages but does not forbid them), so accept the full 1024..=8192
    // range — the stricter 2048-minimum verifier rejects them and produces
    // a false Bogus. Matches the behaviour of unbound/bind validators.
    match algorithm {
        5 | 7 => verify_rsa(
            &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            data,
            sig,
            dnskey,
        ),
        8 => verify_rsa(
            &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
            data,
            sig,
            dnskey,
        ),
        10 => verify_rsa(
            &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
            data,
            sig,
            dnskey,
        ),
        13 => verify_ecdsa::<64>(
            &signature::ECDSA_P256_SHA256_FIXED,
            "ECDSA P-256",
            data,
            sig,
            dnskey,
        ),
        14 => verify_ecdsa::<96>(
            &signature::ECDSA_P384_SHA384_FIXED,
            "ECDSA P-384",
            data,
            sig,
            dnskey,
        ),
        15 => verify_ed25519(data, sig, dnskey),
        16 => Err(DomainError::InvalidDnsResponse(
            "Ed448 (algorithm 16) is not supported by this build".into(),
        )),
        _ => Err(DomainError::InvalidDnsResponse(format!(
            "Unsupported DNSSEC algorithm: {algorithm}"
        ))),
    }
}

/// Whether this build implements the given DNSSEC signature algorithm
/// (matches the dispatch arms in [`verify_signature`]). Used to decide,
/// per RFC 6840 §5.2, whether a zone whose DS RRset names only algorithms we
/// cannot process must be treated as Insecure rather than Bogus.
pub fn is_supported_algorithm(algorithm: u8) -> bool {
    matches!(algorithm, 5 | 7 | 8 | 10 | 13 | 14 | 15)
}

pub fn verify_ds(
    ds: &DsRecord,
    dnskey: &DnskeyRecord,
    owner_name: &str,
) -> Result<bool, DomainError> {
    if dnskey.calculate_key_tag() != ds.key_tag || dnskey.algorithm != ds.algorithm {
        return Ok(false);
    }

    match ds.digest_type {
        1 => dnskey_digest_matches::<Sha1>(dnskey, owner_name, &ds.digest),
        2 => dnskey_digest_matches::<Sha256>(dnskey, owner_name, &ds.digest),
        4 => dnskey_digest_matches::<Sha384>(dnskey, owner_name, &ds.digest),
        _ => Err(DomainError::InvalidDnsResponse(format!(
            "Unsupported DS digest type: {}",
            ds.digest_type
        ))),
    }
}

/// RFC 4034 §5.1.4: digest = hash(canonical owner name | DNSKEY RDATA), fed to
/// the hasher piecewise instead of assembled in a buffer.
fn dnskey_digest_matches<D: Digest>(
    dnskey: &DnskeyRecord,
    owner_name: &str,
    expected: &[u8],
) -> Result<bool, DomainError> {
    let mut hasher = D::new();
    hash_canonical_name(&mut hasher, owner_name)?;
    hasher.update(dnskey.flags.to_be_bytes());
    hasher.update([dnskey.protocol, dnskey.algorithm]);
    hasher.update(&dnskey.public_key);
    Ok(hasher.finalize().as_slice() == expected)
}

fn verify_rsa(
    params: &'static signature::RsaParameters,
    data: &[u8],
    sig: &[u8],
    dnskey: &DnskeyRecord,
) -> Result<bool, DomainError> {
    let (exponent, modulus) = parse_rsa_key(&dnskey.public_key)?;
    let public_key = signature::RsaPublicKeyComponents {
        n: modulus,
        e: exponent,
    };
    Ok(public_key.verify(params, data, sig).is_ok())
}

/// `KEY_LEN` is the uncompressed point without its 0x04 prefix (RFC 6605 §4),
/// which is also the fixed-width `r || s` signature length.
fn verify_ecdsa<const KEY_LEN: usize>(
    alg: &'static signature::EcdsaVerificationAlgorithm,
    name: &str,
    data: &[u8],
    sig: &[u8],
    dnskey: &DnskeyRecord,
) -> Result<bool, DomainError> {
    if dnskey.public_key.len() != KEY_LEN {
        return Err(DomainError::InvalidDnsResponse(format!(
            "Invalid {name} public key length"
        )));
    }
    if sig.len() != KEY_LEN {
        return Err(DomainError::InvalidDnsResponse(format!(
            "Invalid {name} signature length"
        )));
    }

    // Sized for the largest supported curve (P-384).
    let mut point = [0u8; 97];
    point[0] = 0x04;
    point[1..=KEY_LEN].copy_from_slice(&dnskey.public_key);

    Ok(signature::UnparsedPublicKey::new(alg, &point[..=KEY_LEN])
        .verify(data, sig)
        .is_ok())
}

fn verify_ed25519(data: &[u8], sig: &[u8], dnskey: &DnskeyRecord) -> Result<bool, DomainError> {
    if dnskey.public_key.len() != 32 {
        return Err(DomainError::InvalidDnsResponse(
            "Invalid Ed25519 public key length".into(),
        ));
    }
    if sig.len() != 64 {
        return Err(DomainError::InvalidDnsResponse(
            "Invalid Ed25519 signature length".into(),
        ));
    }

    Ok(
        signature::UnparsedPublicKey::new(&signature::ED25519, &dnskey.public_key)
            .verify(data, sig)
            .is_ok(),
    )
}

/// Splits RFC 3110 RSA key material into (exponent, modulus).
fn parse_rsa_key(key_data: &[u8]) -> Result<(&[u8], &[u8]), DomainError> {
    let (exp_len, exp_start) = match key_data {
        [] => {
            return Err(DomainError::InvalidDnsResponse(
                "Empty RSA public key".into(),
            ))
        }
        [0, hi, lo, ..] => (usize::from(u16::from_be_bytes([*hi, *lo])), 3),
        [0, ..] => {
            return Err(DomainError::InvalidDnsResponse(
                "RSA key too short for long form".into(),
            ))
        }
        [len, ..] => (usize::from(*len), 1),
    };

    let exp_end = exp_start + exp_len;
    if exp_end > key_data.len() {
        return Err(DomainError::InvalidDnsResponse(
            "RSA exponent extends beyond key data".into(),
        ));
    }

    let (exponent, modulus) = key_data[exp_start..].split_at(exp_len);
    if modulus.is_empty() {
        return Err(DomainError::InvalidDnsResponse(
            "RSA modulus is empty".into(),
        ));
    }

    Ok((exponent, modulus))
}

/// Feeds the canonical (lowercased, RFC 4034 §6.2) wire form of a presentation
/// name to `hasher`, one label at a time.
fn hash_canonical_name(hasher: &mut impl Digest, name: &str) -> Result<(), DomainError> {
    let name = name.trim_end_matches('.');
    if !name.is_empty() {
        for label in name.split('.') {
            if label.is_empty() {
                return Err(DomainError::InvalidDnsResponse("Empty DNS label".into()));
            }
            if label.len() > 63 {
                return Err(DomainError::InvalidDnsResponse("DNS label too long".into()));
            }
            let mut wire = [0u8; 64];
            wire[0] = label.len() as u8;
            for (dst, src) in wire[1..].iter_mut().zip(label.bytes()) {
                *dst = src.to_ascii_lowercase();
            }
            hasher.update(&wire[..=label.len()]);
        }
    }
    hasher.update([0u8]);
    Ok(())
}
