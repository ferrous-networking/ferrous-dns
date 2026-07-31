//! Anti-downgrade: an *empty* DS answer must be backed by an authenticated
//! denial before the delegation is declared insecure.
//!
//! An empty DS RRset needs no signature to fabricate, so accepting it on sight
//! lets one won race strip DNSSEC from a signed zone. `ChainVerifier` therefore
//! runs the parent's NSEC/NSEC3 through `prove_denial` before returning
//! `InsecureDelegation`. These tests pin the two halves of that check that are
//! deterministic: the DS-specific proof shapes, and the rule that an
//! unauthenticated proof counts as no proof at all (which is what makes the
//! check fail *open* rather than SERVFAIL behind authority-stripping
//! forwarders). Signature math and the full walk stay with the live smoke tests,
//! matching `dnssec_denial_test.rs`.

use data_encoding::BASE32_DNSSEC;
use ferrous_dns_infrastructure::dns::dnssec::validation::authority::collect_verified_denial;
use ferrous_dns_infrastructure::dns::dnssec::validation::denial::{
    prove_denial, VerifiedNsec, VerifiedNsec3,
};
use ferrous_dns_infrastructure::dns::dnssec::validation::ValidationResult;
use ferrous_dns_infrastructure::dns::dnssec::{DnskeyRecord, SignatureVerifier};
use hickory_proto::dnssec::rdata::{DNSSECRData, NSEC, NSEC3};
use hickory_proto::dnssec::Nsec3HashAlgorithm;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::domain::Label;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::str::FromStr;
use std::sync::Arc;

const SALT: &[u8] = &[0xaa, 0xbb];
const ITER: u16 = 10;

/// The delegation under attack, and the parent zone that must prove the absence.
const CHILD: &str = "child.example.com.";
const PARENT: &str = "example.com.";

fn n(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

fn hash(name: &str) -> Vec<u8> {
    Nsec3HashAlgorithm::SHA1
        .hash(SALT, &n(name), ITER)
        .unwrap()
        .as_ref()
        .to_vec()
}

fn label_of(raw: &[u8]) -> Label {
    Label::from_ascii(&BASE32_DNSSEC.encode(raw)).unwrap()
}

fn nsec3(opt_out: bool, next_hash: Vec<u8>, types: &[RecordType]) -> NSEC3 {
    NSEC3::new(
        Nsec3HashAlgorithm::SHA1,
        opt_out,
        ITER,
        SALT.to_vec(),
        next_hash,
        types.iter().copied(),
    )
}

/// Proves "no DS at CHILD" from the given NSEC3 records.
fn prove_ds_absence_nsec3(nsec3s: &[VerifiedNsec3<'_>]) -> ValidationResult {
    prove_denial(
        &n(CHILD),
        RecordType::DS,
        ResponseCode::NoError,
        &n(PARENT),
        nsec3s,
        &[],
    )
}

/// Proves "no DS at CHILD" from the given NSEC records.
fn prove_ds_absence_nsec(nsecs: &[VerifiedNsec<'_>]) -> ValidationResult {
    prove_denial(
        &n(CHILD),
        RecordType::DS,
        ResponseCode::NoError,
        &n(PARENT),
        &[],
        nsecs,
    )
}

// ------------------------- NSEC3 DS NODATA shapes --------------------------

#[test]
fn nsec3_matching_without_ds_bit_proves_absence() {
    // The parent's delegation-point NSEC3: NS present, DS absent.
    let rec = nsec3(false, hash("zzz.example.com."), &[RecordType::NS]);
    let nsec3s = vec![VerifiedNsec3 {
        owner_label: label_of(&hash(CHILD)),
        data: &rec,
    }];
    assert_eq!(prove_ds_absence_nsec3(&nsec3s), ValidationResult::Secure);
}

#[test]
fn nsec3_matching_with_ds_bit_contradicts_the_empty_answer() {
    // The parent says a DS exists while the answer claims none — a downgrade
    // attempt, not an unsigned delegation.
    let rec = nsec3(
        false,
        hash("zzz.example.com."),
        &[RecordType::NS, RecordType::DS],
    );
    let nsec3s = vec![VerifiedNsec3 {
        owner_label: label_of(&hash(CHILD)),
        data: &rec,
    }];
    assert_eq!(prove_ds_absence_nsec3(&nsec3s), ValidationResult::Bogus);
}

#[test]
fn nsec3_matching_from_the_child_side_is_unusable_not_bogus() {
    // SOA in the bitmap makes this the *child's* own apex NSEC3. RFC 6840 §4.4:
    // the child is not authoritative for its DS RRset, so this cannot prove the
    // DS absent — but it is not evidence of forgery either. Some servers really
    // do answer DS from the child side, so the record is discarded as unusable
    // and the verdict falls through to Insecure. Returning Bogus here would
    // SERVFAIL those legitimate zones.
    let rec = nsec3(
        false,
        hash("zzz.example.com."),
        &[RecordType::SOA, RecordType::NS, RecordType::DNSKEY],
    );
    let nsec3s = vec![VerifiedNsec3 {
        owner_label: label_of(&hash(CHILD)),
        data: &rec,
    }];
    assert_eq!(prove_ds_absence_nsec3(&nsec3s), ValidationResult::Insecure);
}

#[test]
fn insecure_does_not_distinguish_opt_out_from_an_inconclusive_proof() {
    // RFC 5155 §8.6 opt-out ("unsigned delegation, no DS") and "the records
    // present prove nothing" both surface as `Insecure`. That collision is why
    // `confirm_ds_absence` caches the verdict only on `Secure`: a partial
    // forgery lands here, and caching it would outlive the attack.
    let child_hash = hash(CHILD);
    let mut before = child_hash.clone();
    let mut after = child_hash.clone();
    before[0] = 0x00;
    after[0] = 0xff;

    let opt_out = nsec3(true, after, &[RecordType::NS]);
    let covering = vec![VerifiedNsec3 {
        owner_label: label_of(&before),
        data: &opt_out,
    }];
    assert_eq!(
        prove_ds_absence_nsec3(&covering),
        ValidationResult::Insecure
    );

    // An NSEC3 that neither matches nor covers the name proves nothing.
    let unrelated = nsec3(false, hash("b.example.com."), &[RecordType::NS]);
    let inconclusive = vec![VerifiedNsec3 {
        owner_label: label_of(&hash("a.example.com.")),
        data: &unrelated,
    }];
    assert_eq!(
        prove_ds_absence_nsec3(&inconclusive),
        ValidationResult::Insecure
    );
}

// -------------------------- NSEC DS NODATA shapes --------------------------

#[test]
fn nsec_matching_without_ds_bit_proves_absence() {
    let rec = NSEC::new(n("zzz.example.com."), [RecordType::NS, RecordType::RRSIG]);
    let owner = n(CHILD);
    let nsecs = vec![VerifiedNsec {
        owner: &owner,
        data: &rec,
    }];
    assert_eq!(prove_ds_absence_nsec(&nsecs), ValidationResult::Secure);
}

#[test]
fn nsec_matching_with_ds_bit_contradicts_the_empty_answer() {
    let rec = NSEC::new(n("zzz.example.com."), [RecordType::NS, RecordType::DS]);
    let owner = n(CHILD);
    let nsecs = vec![VerifiedNsec {
        owner: &owner,
        data: &rec,
    }];
    assert_eq!(prove_ds_absence_nsec(&nsecs), ValidationResult::Bogus);
}

#[test]
fn nsec_matching_from_the_child_side_is_unusable_not_bogus() {
    // RFC 6840 §4.4 — same wrong-side-of-the-delegation rule as NSEC3.
    let rec = NSEC::new(
        n("zzz.example.com."),
        [RecordType::SOA, RecordType::NS, RecordType::DNSKEY],
    );
    let owner = n(CHILD);
    let nsecs = vec![VerifiedNsec {
        owner: &owner,
        data: &rec,
    }];
    assert_eq!(prove_ds_absence_nsec(&nsecs), ValidationResult::Insecure);
}

#[test]
fn a_child_side_nsec_does_not_shadow_a_valid_parent_side_one() {
    // Order must not decide the outcome: the unusable child-side record is
    // skipped, so the parent-side proof behind it still lands. Returning on the
    // first same-owner match made this depend on upstream record ordering.
    let child_side = NSEC::new(
        n("zzz.example.com."),
        [RecordType::SOA, RecordType::NS, RecordType::DNSKEY],
    );
    let parent_side = NSEC::new(n("zzz.example.com."), [RecordType::NS, RecordType::RRSIG]);
    let owner = n(CHILD);
    let nsecs = vec![
        VerifiedNsec {
            owner: &owner,
            data: &child_side,
        },
        VerifiedNsec {
            owner: &owner,
            data: &parent_side,
        },
    ];
    assert_eq!(prove_ds_absence_nsec(&nsecs), ValidationResult::Secure);
}

#[test]
fn the_child_side_rule_is_scoped_to_ds_queries() {
    // A zone apex legitimately carries SOA; only a *DS* proof has a wrong side.
    // Without this scoping every apex NODATA would turn Bogus.
    let rec = NSEC::new(
        n("zzz.example.com."),
        [RecordType::SOA, RecordType::NS, RecordType::A],
    );
    let owner = n(PARENT);
    let nsecs = vec![VerifiedNsec {
        owner: &owner,
        data: &rec,
    }];
    let result = prove_denial(
        &n(PARENT),
        RecordType::MX,
        ResponseCode::NoError,
        &n(PARENT),
        &[],
        &nsecs,
    );
    assert_eq!(result, ValidationResult::Secure);
}

#[test]
fn no_denial_records_at_all_is_bogus() {
    // Documents why `confirm_ds_absence` must short-circuit *before* calling
    // `prove_denial`: with nothing to verify this reports Bogus, which would
    // SERVFAIL every delegation behind an authority-stripping forwarder.
    assert_eq!(prove_ds_absence_nsec3(&[]), ValidationResult::Bogus);
}

// ------------- unauthenticated proofs count as no proof at all -------------

fn nsec_record(owner: &str, next: &str, types: &[RecordType]) -> Record {
    Record::from_rdata(
        n(owner),
        3600,
        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(n(next), types.iter().copied()))),
    )
}

#[test]
fn nsec_without_an_rrsig_is_not_collected() {
    let authority = vec![nsec_record(CHILD, "zzz.example.com.", &[RecordType::NS])];
    let (nsec3s, nsecs) = collect_verified_denial(&authority, &SignatureVerifier, 0, &|_| None);

    assert!(
        nsec3s.is_empty() && nsecs.is_empty(),
        "an NSEC with no covering RRSIG must not count as a proof"
    );
}

#[test]
fn nsec_whose_signer_zone_has_no_keys_is_not_collected() {
    // The lookup answers for an unrelated zone only, so the RRSIG's signer has
    // no established keys — the record is dropped rather than trusted.
    let authority = vec![nsec_record(CHILD, "zzz.example.com.", &[RecordType::NS])];
    let keys: Arc<[DnskeyRecord]> = Arc::from(vec![DnskeyRecord {
        flags: 256,
        protocol: 3,
        algorithm: 15,
        public_key: vec![0u8; 32],
    }]);
    let (nsec3s, nsecs) = collect_verified_denial(&authority, &SignatureVerifier, 0, &|zone| {
        (zone == "unrelated.test.").then(|| Arc::clone(&keys))
    });

    assert!(
        nsec3s.is_empty() && nsecs.is_empty(),
        "an NSEC signed by a zone outside the chain must not count as a proof"
    );
}
