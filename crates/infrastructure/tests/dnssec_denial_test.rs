//! Deterministic tests for NSEC / NSEC3 authenticated denial of existence.
//!
//! These exercise the pure proof logic in `dns::dnssec::validation::denial`
//! against hand-built NSEC/NSEC3 records (already treated as RRSIG-authentic),
//! so they run without crypto, keys, or the network. RRSIG verification and the
//! full chain are covered by the live smoke tests.

use data_encoding::BASE32_DNSSEC;
use ferrous_dns_infrastructure::dns::dnssec::validation::denial::{
    prove_denial, prove_wildcard_expansion, VerifiedNsec, VerifiedNsec3,
};
use ferrous_dns_infrastructure::dns::dnssec::validation::ValidationResult;
use hickory_proto::dnssec::rdata::{NSEC, NSEC3};
use hickory_proto::dnssec::Nsec3HashAlgorithm;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::domain::Label;
use hickory_proto::rr::{Name, RecordType};
use std::str::FromStr;

const SALT: &[u8] = &[0xaa, 0xbb];
const ITER: u16 = 10;

fn n(s: &str) -> Name {
    Name::from_str(s).unwrap()
}

fn nsec(next: &str, types: &[RecordType]) -> NSEC {
    NSEC::new(n(next), types.iter().copied())
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

fn nsec3(opt_out: bool, iterations: u16, next_hash: Vec<u8>, types: &[RecordType]) -> NSEC3 {
    NSEC3::new(
        Nsec3HashAlgorithm::SHA1,
        opt_out,
        iterations,
        SALT.to_vec(),
        next_hash,
        types.iter().copied(),
    )
}

// ----------------------------- NSEC (NSEC1) --------------------------------

#[test]
fn nsec1_nodata_secure_when_type_absent() {
    let rec = nsec(
        "later.example.com.",
        &[RecordType::A, RecordType::RRSIG, RecordType::NSEC],
    );
    let owner = n("host.example.com.");
    let nsecs = vec![VerifiedNsec {
        owner: &owner,
        data: &rec,
    }];
    let result = prove_denial(
        &n("host.example.com."),
        RecordType::AAAA,
        ResponseCode::NoError,
        &n("example.com."),
        &[],
        &nsecs,
    );
    assert_eq!(result, ValidationResult::Secure);
}

#[test]
fn nsec1_nodata_bogus_when_type_present() {
    let rec = nsec(
        "later.example.com.",
        &[RecordType::A, RecordType::AAAA, RecordType::RRSIG],
    );
    let owner = n("host.example.com.");
    let nsecs = vec![VerifiedNsec {
        owner: &owner,
        data: &rec,
    }];
    let result = prove_denial(
        &n("host.example.com."),
        RecordType::AAAA,
        ResponseCode::NoError,
        &n("example.com."),
        &[],
        &nsecs,
    );
    assert_eq!(result, ValidationResult::Bogus);
}

#[test]
fn nsec1_nxdomain_secure_with_cover_and_wildcard() {
    // Covers the queried name m.example.com (a < m < z).
    let cover = nsec("z.example.com.", &[RecordType::A]);
    let cover_owner = n("a.example.com.");
    // Covers the wildcard *.example.com (example.com < * < a.example.com).
    let wild = nsec("a.example.com.", &[RecordType::SOA, RecordType::NS]);
    let wild_owner = n("example.com.");
    let nsecs = vec![
        VerifiedNsec {
            owner: &cover_owner,
            data: &cover,
        },
        VerifiedNsec {
            owner: &wild_owner,
            data: &wild,
        },
    ];
    let result = prove_denial(
        &n("m.example.com."),
        RecordType::A,
        ResponseCode::NXDomain,
        &n("example.com."),
        &[],
        &nsecs,
    );
    assert_eq!(result, ValidationResult::Secure);
}

#[test]
fn nsec1_nxdomain_bogus_without_wildcard_proof() {
    let cover = nsec("z.example.com.", &[RecordType::A]);
    let cover_owner = n("a.example.com.");
    let nsecs = vec![VerifiedNsec {
        owner: &cover_owner,
        data: &cover,
    }];
    let result = prove_denial(
        &n("m.example.com."),
        RecordType::A,
        ResponseCode::NXDomain,
        &n("example.com."),
        &[],
        &nsecs,
    );
    assert_eq!(result, ValidationResult::Bogus);
}

// ----------------------------- NSEC3 ---------------------------------------

#[test]
fn nsec3_nodata_secure_on_matching_record_without_type() {
    let owner_label = label_of(&hash("absent.example.com."));
    let rec = nsec3(
        false,
        ITER,
        hash("zzzz.example.com."),
        &[RecordType::TXT, RecordType::RRSIG],
    );
    let nsec3s = vec![VerifiedNsec3 {
        owner_label,
        data: &rec,
    }];
    let result = prove_denial(
        &n("absent.example.com."),
        RecordType::A,
        ResponseCode::NoError,
        &n("example.com."),
        &nsec3s,
        &[],
    );
    assert_eq!(result, ValidationResult::Secure);
}

#[test]
fn nsec3_nodata_bogus_when_matching_record_has_type() {
    let owner_label = label_of(&hash("absent.example.com."));
    let rec = nsec3(
        false,
        ITER,
        hash("zzzz.example.com."),
        &[RecordType::A, RecordType::RRSIG],
    );
    let nsec3s = vec![VerifiedNsec3 {
        owner_label,
        data: &rec,
    }];
    let result = prove_denial(
        &n("absent.example.com."),
        RecordType::A,
        ResponseCode::NoError,
        &n("example.com."),
        &nsec3s,
        &[],
    );
    assert_eq!(result, ValidationResult::Bogus);
}

#[test]
fn nsec3_ds_nodata_optout_is_insecure() {
    // A covering opt-out NSEC3 (owner 00.. < hash(qname) < next ff..).
    let owner_label = label_of(&[0u8; 20]);
    let rec = nsec3(true, ITER, vec![0xff; 20], &[RecordType::NS]);
    let nsec3s = vec![VerifiedNsec3 {
        owner_label,
        data: &rec,
    }];
    let result = prove_denial(
        &n("insecure-deleg.example.com."),
        RecordType::DS,
        ResponseCode::NoError,
        &n("example.com."),
        &nsec3s,
        &[],
    );
    assert_eq!(result, ValidationResult::Insecure);
}

#[test]
fn nsec3_high_iterations_is_insecure() {
    // RFC 9276 hardening: iterations above the cap fail open (no SERVFAIL).
    let rec = nsec3(false, 500, vec![0xff; 20], &[RecordType::A]);
    let nsec3s = vec![VerifiedNsec3 {
        owner_label: label_of(&[0u8; 20]),
        data: &rec,
    }];
    let result = prove_denial(
        &n("x.example.com."),
        RecordType::A,
        ResponseCode::NXDomain,
        &n("example.com."),
        &nsec3s,
        &[],
    );
    assert_eq!(result, ValidationResult::Insecure);
}

// ------------------- wildcard expansion (RFC 4035 §5.3.4) ------------------

#[test]
fn wildcard_expansion_secure_when_exact_name_denied() {
    // Positive answer at foo.example.com synthesized from *.example.com; an NSEC
    // covering foo.example.com proves the exact name does not exist.
    let cover = nsec("z.example.com.", &[RecordType::A]);
    let owner = n("a.example.com.");
    let nsecs = vec![VerifiedNsec {
        owner: &owner,
        data: &cover,
    }];
    let result = prove_wildcard_expansion(&n("foo.example.com."), 2, &[], &nsecs);
    assert_eq!(result, ValidationResult::Secure);
}

#[test]
fn wildcard_expansion_bogus_when_exact_name_not_denied() {
    // No NSEC denies foo.example.com → the claimed wildcard expansion is forged.
    let other = nsec("a.example.com.", &[RecordType::SOA]);
    let owner = n("example.com.");
    let nsecs = vec![VerifiedNsec {
        owner: &owner,
        data: &other,
    }];
    let result = prove_wildcard_expansion(&n("foo.example.com."), 2, &[], &nsecs);
    assert_eq!(result, ValidationResult::Bogus);
}

#[test]
fn no_denial_records_is_bogus() {
    // Signed zone, negative answer, but the proof records were stripped.
    let result = prove_denial(
        &n("x.example.com."),
        RecordType::A,
        ResponseCode::NXDomain,
        &n("example.com."),
        &[],
        &[],
    );
    assert_eq!(result, ValidationResult::Bogus);
}
