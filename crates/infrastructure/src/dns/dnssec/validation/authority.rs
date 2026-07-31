//! Authenticity checks over an authority/answer section, shared by the two
//! consumers that need them: [`DnssecValidator`](crate::dns::dnssec::DnssecValidator),
//! which proves denial for a client-facing response, and
//! [`ChainVerifier`](super::ChainVerifier), which proves absence of a DS RRset
//! mid-walk.
//!
//! These are free functions rather than methods because the two callers sit on
//! opposite ends of an ownership edge — `DnssecValidator` *owns* the
//! `ChainVerifier`, so the chain walk cannot call back into the validator. Both
//! only need a way to look up the DNSKEYs of an already-validated zone, which
//! they pass in as [`KeyLookup`].

use super::super::crypto::SignatureVerifier;
use super::super::types::{DnskeyRecord, RrsigRecord};
use super::denial::{VerifiedNsec, VerifiedNsec3};
use crate::dns::forwarding::record_type_map::RecordTypeMapper;
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::rr::domain::Label;
use hickory_proto::rr::{Name, RData, Record};
use std::sync::Arc;
use tracing::debug;

/// Resolves a signer zone name to the DNSKEYs already established for it in the
/// chain of trust. Returning `None` means "no authenticated keys for this zone",
/// which makes every RRSIG naming it unverifiable.
pub type KeyLookup<'a> = &'a dyn Fn(&str) -> Option<Arc<[DnskeyRecord]>>;

/// True when `zone` is `qname` itself or one of its ancestors, i.e. `zone`
/// encloses `qname`. Label comparison is the DNS-canonical (case-folded)
/// equality of [`Name`].
pub fn name_encloses(zone: &Name, qname: &Name) -> bool {
    let (zone_labels, qname_labels) = (zone.num_labels(), qname.num_labels());
    if zone_labels > qname_labels {
        return false;
    }
    let mut ancestor = qname.clone();
    for _ in 0..(qname_labels - zone_labels) {
        ancestor = ancestor.base_name();
    }
    &ancestor == zone
}

/// True when the `rrset` (every record sharing `owner` + `rtype`) is covered
/// by a valid RRSIG in `sigs`, signed by a key already established in the
/// chain of trust. Used both for single-record NSEC/NSEC3 authority RRsets
/// and for multi-record positive-answer RRsets.
pub fn rrset_is_authentic(
    owner: &Name,
    rtype: hickory_proto::rr::RecordType,
    rrset: &[Record],
    sigs: &[Record],
    crypto: &SignatureVerifier,
    now_secs: u32,
    key_lookup: KeyLookup<'_>,
) -> bool {
    let mut outcome = "no-rrsig";

    for sig in sigs {
        let RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) = &sig.data else {
            continue;
        };
        if &sig.name != owner {
            continue;
        }
        let input = rrsig.input();
        if input.type_covered != rtype {
            continue;
        }
        // RFC 4035 §5.3.1: the RRSIG's signer name must be the apex of the
        // zone authoritative for the RRset, i.e. it MUST enclose the owner
        // name. The signature math does not bind signer⊇owner — only the key
        // identity — so without this check an attacker who controls *any*
        // validly-signed zone (which chains to root, so its keys land in
        // `validated_keys` once `extract_signer_zones` drives a walk for it)
        // could sign a forged RRset for an unrelated victim name with their
        // own key and have it accepted as Secure / AD=1.
        if !name_encloses(&input.signer_name, owner) {
            outcome = "signer-not-enclosing";
            continue;
        }
        let Some(type_covered) = RecordTypeMapper::from_hickory(input.type_covered) else {
            continue;
        };
        let rr = RrsigRecord {
            type_covered,
            algorithm: u8::from(input.algorithm),
            labels: input.num_labels,
            original_ttl: input.original_ttl,
            signature_expiration: input.sig_expiration.get(),
            signature_inception: input.sig_inception.get(),
            key_tag: input.key_tag,
            signer_name: input.signer_name.to_string(),
            signature: rrsig.sig().to_vec(),
        };
        let Some(keys) = key_lookup(&rr.signer_name) else {
            outcome = "no-keys";
            continue;
        };
        for key in keys.iter() {
            match crypto.verify_rrsig_with_name(&rr, key, owner, rrset, now_secs) {
                Ok(true) => return true,
                Ok(false) => outcome = "sig-false",
                Err(_) => outcome = "sig-err",
            }
        }
    }
    debug!(owner = %owner, ?rtype, outcome, "rrset not authentic");
    false
}

/// Collects the cryptographically-authentic NSEC3 and NSEC records from an
/// authority section.
pub fn collect_verified_denial<'a>(
    authority: &'a [Record],
    crypto: &SignatureVerifier,
    now_secs: u32,
    key_lookup: KeyLookup<'_>,
) -> (Vec<VerifiedNsec3<'a>>, Vec<VerifiedNsec<'a>>) {
    let mut nsec3s: Vec<VerifiedNsec3<'a>> = Vec::new();
    let mut nsecs: Vec<VerifiedNsec<'a>> = Vec::new();

    for record in authority {
        match &record.data {
            RData::DNSSEC(DNSSECRData::NSEC3(nsec3))
                if rrset_is_authentic(
                    &record.name,
                    record.record_type(),
                    std::slice::from_ref(record),
                    authority,
                    crypto,
                    now_secs,
                    key_lookup,
                ) =>
            {
                if let Some(label) = record
                    .name
                    .iter()
                    .next()
                    .and_then(|first| Label::from_raw_bytes(first).ok())
                {
                    nsec3s.push(VerifiedNsec3 {
                        owner_label: label,
                        data: nsec3,
                    });
                }
            }
            RData::DNSSEC(DNSSECRData::NSEC(nsec))
                if rrset_is_authentic(
                    &record.name,
                    record.record_type(),
                    std::slice::from_ref(record),
                    authority,
                    crypto,
                    now_secs,
                    key_lookup,
                ) =>
            {
                nsecs.push(VerifiedNsec {
                    owner: &record.name,
                    data: nsec,
                });
            }
            _ => {}
        }
    }
    (nsec3s, nsecs)
}
