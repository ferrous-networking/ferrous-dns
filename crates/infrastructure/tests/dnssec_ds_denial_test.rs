//! Anti-downgrade: an *empty* DS answer only lets the chain walk past a name
//! when the parent zone's authenticated NSEC/NSEC3 proves what the absence
//! means. `classify_ds_denial` turns the proof into that meaning — unsigned
//! delegation, plain name inside the parent zone, or nonexistent name — and
//! refuses (`None`) anything else, which the walk reports as Bogus. Signature
//! math and the walk itself are covered end to end in `dnssec_chain_walk_test.rs`.

use data_encoding::BASE32_DNSSEC;
use ferrous_dns_domain::DnssecStatus;
use ferrous_dns_infrastructure::dns::dnssec::validation::authority::collect_verified_denial;
use ferrous_dns_infrastructure::dns::dnssec::validation::denial::{
    classify_ds_denial, prove_denial, VerifiedNsec, VerifiedNsec3,
};
use ferrous_dns_infrastructure::dns::dnssec::{DnskeyRecord, DsDenial};
use hickory_proto::dnssec::rdata::{DNSSECRData, NSEC, NSEC3};
use hickory_proto::dnssec::Nsec3HashAlgorithm;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::domain::Label;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use std::str::FromStr;
use std::sync::Arc;

const SALT: &[u8] = &[0xaa, 0xbb];
const ITER: u16 = 10;

/// The name whose DS was asked for, and the parent zone that must prove the absence.
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

fn nodata_nsec3(nsec3s: &[VerifiedNsec3<'_>]) -> Option<DsDenial> {
    classify_ds_denial(&n(CHILD), ResponseCode::NoError, &n(PARENT), nsec3s, &[])
}

fn nodata_nsec(nsecs: &[VerifiedNsec<'_>]) -> Option<DsDenial> {
    classify_ds_denial(&n(CHILD), ResponseCode::NoError, &n(PARENT), &[], nsecs)
}

/// A single NSEC3 owned by CHILD's hash.
fn at_child(rec: &NSEC3) -> Vec<VerifiedNsec3<'_>> {
    vec![VerifiedNsec3 {
        owner_label: label_of(&hash(CHILD)),
        data: rec,
    }]
}

// ------------------------- NSEC3 DS NODATA shapes --------------------------

#[test]
fn nsec3_delegation_without_ds_is_an_insecure_delegation() {
    let rec = nsec3(false, hash("zzz.example.com."), &[RecordType::NS]);
    assert_eq!(
        nodata_nsec3(&at_child(&rec)),
        Some(DsDenial::InsecureDelegation)
    );
}

#[test]
fn nsec3_name_without_ns_is_not_a_zone_cut() {
    // A plain host in the parent zone: the walk keeps the parent's keys, so an
    // unsigned answer for it is Bogus rather than Insecure.
    let rec = nsec3(
        false,
        hash("zzz.example.com."),
        &[RecordType::A, RecordType::RRSIG],
    );
    assert_eq!(nodata_nsec3(&at_child(&rec)), Some(DsDenial::NotZoneCut));
}

#[test]
fn nsec3_with_ds_bit_contradicts_the_empty_answer() {
    let rec = nsec3(
        false,
        hash("zzz.example.com."),
        &[RecordType::NS, RecordType::DS],
    );
    assert_eq!(nodata_nsec3(&at_child(&rec)), None);
}

#[test]
fn nsec3_from_the_child_side_proves_nothing() {
    // SOA in the bitmap makes this the child's own apex record; the child is
    // not authoritative for its DS (RFC 6840 §4.4).
    let rec = nsec3(
        false,
        hash("zzz.example.com."),
        &[RecordType::SOA, RecordType::NS, RecordType::DNSKEY],
    );
    assert_eq!(nodata_nsec3(&at_child(&rec)), None);
}

#[test]
fn nsec3_opt_out_needs_a_closest_encloser_proof() {
    // RFC 5155 §8.6: an opt-out span over the next closer only counts next to
    // a matching NSEC3 for the closest encloser.
    let child_hash = hash(CHILD);
    let mut before = child_hash.clone();
    let mut after = child_hash;
    before[0] = 0x00;
    after[0] = 0xff;
    let opt_out = nsec3(true, after, &[RecordType::NS]);
    let apex = nsec3(
        false,
        hash("zzzz.example.com."),
        &[RecordType::SOA, RecordType::NS, RecordType::DNSKEY],
    );
    let cover = VerifiedNsec3 {
        owner_label: label_of(&before),
        data: &opt_out,
    };
    let ce = VerifiedNsec3 {
        owner_label: label_of(&hash(PARENT)),
        data: &apex,
    };

    assert_eq!(nodata_nsec3(std::slice::from_ref(&cover)), None);
    assert_eq!(
        nodata_nsec3(&[cover, ce]),
        Some(DsDenial::InsecureDelegation)
    );
}

#[test]
fn nsec3_that_neither_matches_nor_covers_proves_nothing() {
    let unrelated = nsec3(false, hash("b.example.com."), &[RecordType::NS]);
    let nsec3s = vec![VerifiedNsec3 {
        owner_label: label_of(&hash("a.example.com.")),
        data: &unrelated,
    }];
    assert_eq!(nodata_nsec3(&nsec3s), None);
}

// -------------------------- NSEC DS NODATA shapes --------------------------

/// Classifies a single NSEC owned by CHILD with the given type bitmap.
fn nodata_nsec_at_child(types: &[RecordType]) -> Option<DsDenial> {
    let rec = NSEC::new(n("zzz.example.com."), types.iter().copied());
    let owner = n(CHILD);
    nodata_nsec(&[VerifiedNsec {
        owner: &owner,
        data: &rec,
    }])
}

#[test]
fn nsec_delegation_without_ds_is_an_insecure_delegation() {
    assert_eq!(
        nodata_nsec_at_child(&[RecordType::NS, RecordType::RRSIG]),
        Some(DsDenial::InsecureDelegation)
    );
}

#[test]
fn nsec_name_without_ns_is_not_a_zone_cut() {
    assert_eq!(
        nodata_nsec_at_child(&[RecordType::A, RecordType::RRSIG]),
        Some(DsDenial::NotZoneCut)
    );
}

#[test]
fn nsec_with_ds_bit_contradicts_the_empty_answer() {
    assert_eq!(
        nodata_nsec_at_child(&[RecordType::NS, RecordType::DS]),
        None
    );
}

#[test]
fn nsec_from_the_child_side_proves_nothing() {
    assert_eq!(
        nodata_nsec_at_child(&[RecordType::SOA, RecordType::NS, RecordType::DNSKEY]),
        None
    );
}

#[test]
fn a_child_side_nsec_does_not_shadow_a_valid_parent_side_one() {
    // Order must not decide the outcome: the unusable child-side record is
    // skipped, so the parent-side proof behind it still lands.
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
    assert_eq!(nodata_nsec(&nsecs), Some(DsDenial::InsecureDelegation));
}

#[test]
fn nsec_empty_non_terminal_is_not_a_zone_cut() {
    // CHILD has no records of its own but a descendant does: the NSEC before
    // it covers CHILD and names that descendant next (RFC 4035 §3.1.3.2).
    let rec = NSEC::new(n("host.child.example.com."), [RecordType::A]);
    let owner = n("aaa.example.com.");
    let nsecs = vec![VerifiedNsec {
        owner: &owner,
        data: &rec,
    }];
    assert_eq!(nodata_nsec(&nsecs), Some(DsDenial::NotZoneCut));
}

#[test]
fn nsec_nxdomain_proof_marks_the_name_nonexistent() {
    let cover = NSEC::new(n("zzz.example.com."), [RecordType::A]);
    let apex = NSEC::new(n("aaa.example.com."), [RecordType::SOA, RecordType::NS]);
    let (cover_owner, apex_owner) = (n("bbb.example.com."), n(PARENT));
    let nsecs = vec![
        VerifiedNsec {
            owner: &cover_owner,
            data: &cover,
        },
        VerifiedNsec {
            owner: &apex_owner,
            data: &apex,
        },
    ];
    assert_eq!(
        classify_ds_denial(&n(CHILD), ResponseCode::NXDomain, &n(PARENT), &[], &nsecs),
        Some(DsDenial::Nonexistent)
    );
}

#[test]
fn no_denial_records_prove_nothing() {
    assert_eq!(nodata_nsec3(&[]), None);
    assert_eq!(nodata_nsec(&[]), None);
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
    assert_eq!(result, DnssecStatus::Secure);
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
    let (nsec3s, nsecs) = collect_verified_denial(&authority, 0, &|_| None);

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
    let unrelated = n("unrelated.test.");
    let (nsec3s, nsecs) = collect_verified_denial(&authority, 0, &|zone| {
        (zone == &unrelated).then(|| Arc::clone(&keys))
    });

    assert!(
        nsec3s.is_empty() && nsecs.is_empty(),
        "an NSEC signed by a zone outside the chain must not count as a proof"
    );
}
