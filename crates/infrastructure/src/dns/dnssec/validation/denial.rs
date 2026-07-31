//! Authenticated denial of existence (RFC 4035 §5.4, RFC 5155, RFC 9276).
//!
//! Given the NSEC / NSEC3 records of a negative response's authority section —
//! already proven authentic by their RRSIGs — these routines decide whether the
//! denial (NXDOMAIN / NODATA) is actually proven for the queried name and type.
//!
//! Mapping to [`ValidationResult`]:
//! * `Secure` — the denial is fully proven.
//! * `Insecure` — the denial points at an unsigned (opt-out) delegation, or the
//!   NSEC3 iteration count is above the hardening cap; serve without AD.
//! * `Bogus` — the zone is signed but the denial is unproven / forged.
//!
//! The matching logic follows the structure of unbound / hickory's validator but
//! is implemented here against the project's own chain-of-trust machinery.

use super::chain::ValidationResult;
use data_encoding::BASE32_DNSSEC;
use hickory_proto::dnssec::rdata::{NSEC, NSEC3};
use hickory_proto::dnssec::Nsec3HashAlgorithm;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::domain::Label;
use hickory_proto::rr::{Name, RecordType};

/// NSEC3 iterations above this are treated as `Insecure` (RFC 9276 hardening).
/// Bounds CPU spent hashing before any proof work happens.
const NSEC3_ITERATION_CAP: u16 = 100;

/// A verified NSEC record paired with its owner name.
pub struct VerifiedNsec<'a> {
    pub owner: &'a Name,
    pub data: &'a NSEC,
}

/// A verified NSEC3 record paired with its (base32) owner label.
pub struct VerifiedNsec3<'a> {
    pub owner_label: Label,
    pub data: &'a NSEC3,
}

/// Entry point: prove a negative response using the verified NSEC/NSEC3 records.
///
pub fn prove_denial(
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
    soa_name: &Name,
    nsec3s: &[VerifiedNsec3<'_>],
    nsecs: &[VerifiedNsec<'_>],
) -> ValidationResult {
    if !nsec3s.is_empty() {
        verify_nsec3(qname, qtype, rcode, soa_name, nsec3s)
    } else if !nsecs.is_empty() {
        verify_nsec1(qname, qtype, rcode, soa_name, nsecs)
    } else {
        // Signed zone, negative answer, but no denial records at all: stripped.
        ValidationResult::Bogus
    }
}

// ============================ NSEC3 (RFC 5155) =============================

fn verify_nsec3(
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
    soa_name: &Name,
    nsec3s: &[VerifiedNsec3<'_>],
) -> ValidationResult {
    // RFC 5155 §8.2 — all NSEC3 RRs in the proof share the same parameters.
    let first = &nsec3s[0];
    let salt = first.data.salt();
    let iterations = first.data.iterations();
    if nsec3s.iter().any(|r| {
        r.data.hash_algorithm() != first.data.hash_algorithm()
            || r.data.salt() != salt
            || r.data.iterations() != iterations
    }) {
        return ValidationResult::Bogus;
    }

    // RFC 9276 §3.2 hardening: refuse to spend CPU on high iteration counts.
    if iterations > NSEC3_ITERATION_CAP {
        return ValidationResult::Insecure;
    }

    match rcode {
        ResponseCode::NXDomain => nsec3_nxdomain(qname, soa_name, salt, iterations, nsec3s),
        ResponseCode::NoError => nsec3_nodata(qname, qtype, soa_name, salt, iterations, nsec3s),
        _ => ValidationResult::Bogus,
    }
}

/// Hash `name` and return (raw digest, base32 label). `None` on hashing failure.
fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Option<(Vec<u8>, Label)> {
    let digest = Nsec3HashAlgorithm::SHA1.hash(salt, name, iterations).ok()?;
    let raw = digest.as_ref().to_vec();
    let label = Label::from_ascii(&BASE32_DNSSEC.encode(&raw)).ok()?;
    Some((raw, label))
}

/// True when `target` falls in the (owner, next] interval of the NSEC3 record,
/// i.e. the record *covers* the target hash. Owner side compares base32 labels,
/// next side compares raw hashes (both orderings are equivalent).
fn nsec3_covers(record: &VerifiedNsec3<'_>, target_raw: &[u8], target_label: &Label) -> bool {
    let Some(next_label) = record.data.next_hashed_owner_name_base32() else {
        return false;
    };
    let next_raw = record.data.next_hashed_owner_name();
    if record.owner_label < *next_label {
        // Ordinary interval.
        record.owner_label < *target_label && target_raw < next_raw
    } else {
        // Wrap-around at the end of the zone's hash circle.
        record.owner_label > *target_label || target_raw > next_raw
    }
}

fn nsec3_find_covering<'a>(
    nsec3s: &'a [VerifiedNsec3<'a>],
    target_raw: &[u8],
    target_label: &Label,
) -> Option<&'a VerifiedNsec3<'a>> {
    nsec3s
        .iter()
        .find(|r| nsec3_covers(r, target_raw, target_label))
}

fn nsec3_find_matching<'a>(
    nsec3s: &'a [VerifiedNsec3<'a>],
    target_label: &Label,
) -> Option<&'a VerifiedNsec3<'a>> {
    nsec3s.iter().find(|r| r.owner_label == *target_label)
}

/// Ancestor chain of `qname` up to and including `soa_name` (longest first).
fn encloser_candidates(qname: &Name, soa_name: &Name) -> Vec<Name> {
    let mut out = Vec::with_capacity(qname.num_labels() as usize);
    let mut name = qname.clone();
    loop {
        out.push(name.clone());
        if &name == soa_name {
            return out;
        }
        let parent = name.base_name();
        if parent.is_root() {
            // qname is not under soa_name — malformed proof.
            return out;
        }
        name = parent;
    }
}

/// RFC 5155 §8.4 — NXDOMAIN closest-encloser proof.
fn nsec3_nxdomain(
    qname: &Name,
    soa_name: &Name,
    salt: &[u8],
    iterations: u16,
    nsec3s: &[VerifiedNsec3<'_>],
) -> ValidationResult {
    // NXDOMAIN must not carry a matching NSEC3 for the query name itself.
    if let Some((_, qlabel)) = nsec3_hash(qname, salt, iterations) {
        if nsec3_find_matching(nsec3s, &qlabel).is_some() {
            return ValidationResult::Bogus;
        }
    }

    let candidates = encloser_candidates(qname, soa_name);

    // Find the closest encloser: the longest candidate with a *matching* NSEC3.
    for (idx, ce) in candidates.iter().enumerate() {
        let Some((_, ce_label)) = nsec3_hash(ce, salt, iterations) else {
            continue;
        };
        if nsec3_find_matching(nsec3s, &ce_label).is_none() {
            continue;
        }
        // idx == 0 would mean qname itself matches → contradicts NXDOMAIN.
        if idx == 0 {
            return ValidationResult::Bogus;
        }
        // Next closer = the candidate one label longer than the closest encloser.
        let next_closer = &candidates[idx - 1];
        let Some((nc_raw, nc_label)) = nsec3_hash(next_closer, salt, iterations) else {
            return ValidationResult::Bogus;
        };
        let Some(nc_record) = nsec3_find_covering(nsec3s, &nc_raw, &nc_label) else {
            return ValidationResult::Bogus;
        };
        // Opt-out over the next closer → the (insecure) name may exist unsigned.
        if nc_record.data.opt_out() {
            return ValidationResult::Insecure;
        }
        // Wildcard at the closest encloser must be covered (proven absent).
        let Some(wildcard) = make_wildcard(ce) else {
            return ValidationResult::Bogus;
        };
        let Some((wc_raw, wc_label)) = nsec3_hash(&wildcard, salt, iterations) else {
            return ValidationResult::Bogus;
        };
        return match nsec3_find_covering(nsec3s, &wc_raw, &wc_label) {
            Some(_) => ValidationResult::Secure,
            None => ValidationResult::Bogus,
        };
    }

    // No matching closest encloser found.
    ValidationResult::Bogus
}

/// RFC 5155 §8.5–8.7 — NODATA proofs.
fn nsec3_nodata(
    qname: &Name,
    qtype: RecordType,
    soa_name: &Name,
    salt: &[u8],
    iterations: u16,
    nsec3s: &[VerifiedNsec3<'_>],
) -> ValidationResult {
    let Some((q_raw, q_label)) = nsec3_hash(qname, salt, iterations) else {
        return ValidationResult::Bogus;
    };

    // §8.5 / §8.6 — an NSEC3 matching QNAME with QTYPE and CNAME absent.
    if let Some(record) = nsec3_find_matching(nsec3s, &q_label) {
        // RFC 6840 §4.4: an NSEC3 from the *child* side of a delegation cannot
        // deny a DS, because the DS lives in the parent. Some servers answer DS
        // from the child side anyway, so such a record is unusable as proof —
        // not evidence of forgery. Fall through to the remaining proofs instead
        // of returning Bogus, which would SERVFAIL a legitimate zone.
        let usable =
            !(qtype == RecordType::DS && wrong_side_of_delegation(record.data.type_bit_maps()));
        if usable {
            let has_type = record.data.type_bit_maps().any(|t| t == qtype);
            let has_cname = record.data.type_bit_maps().any(|t| t == RecordType::CNAME);
            if has_type || has_cname {
                return ValidationResult::Bogus;
            }
            return ValidationResult::Secure;
        }
    }

    // §8.6 — DS NODATA via opt-out: covering NSEC3 with the opt-out bit set.
    if qtype == RecordType::DS {
        if let Some(record) = nsec3_find_covering(nsec3s, &q_raw, &q_label) {
            if record.data.opt_out() {
                return ValidationResult::Insecure;
            }
        }
    }

    // §8.7 — wildcard NODATA: closest-encloser proof for a servicing wildcard.
    if wildcard_based_encloser(qname, soa_name, salt, iterations, nsec3s) {
        return ValidationResult::Secure;
    }

    // Signed NSEC3 records are present but none conclusively prove this NODATA.
    // Fail open (served without AD) rather than SERVFAIL a possibly valid name.
    ValidationResult::Insecure
}

/// Wildcard closest-encloser proof (RFC 5155 §8.7): a *matching* wildcard NSEC3
/// plus a *covering* next closer.
fn wildcard_based_encloser(
    qname: &Name,
    soa_name: &Name,
    salt: &[u8],
    iterations: u16,
    nsec3s: &[VerifiedNsec3<'_>],
) -> bool {
    let candidates = encloser_candidates(qname, soa_name);
    // Wildcards of each proper ancestor (skip qname itself). `ce` is at index
    // `idx`; its next closer is the candidate one label longer (`idx - 1`).
    for idx in 1..candidates.len() {
        let ce = &candidates[idx];
        let Some(wildcard) = make_wildcard(ce) else {
            continue;
        };
        let Some((_, wc_label)) = nsec3_hash(&wildcard, salt, iterations) else {
            continue;
        };
        if nsec3_find_matching(nsec3s, &wc_label).is_none() {
            continue;
        }
        let next_closer = &candidates[idx - 1];
        let Some((nc_raw, nc_label)) = nsec3_hash(next_closer, salt, iterations) else {
            continue;
        };
        if nsec3_find_covering(nsec3s, &nc_raw, &nc_label).is_some() {
            return true;
        }
    }
    false
}

fn make_wildcard(name: &Name) -> Option<Name> {
    Name::new().append_label("*").ok()?.append_name(name).ok()
}

// ============================ NSEC (RFC 4034/4035) =========================

fn verify_nsec1(
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
    soa_name: &Name,
    nsecs: &[VerifiedNsec<'_>],
) -> ValidationResult {
    match rcode {
        ResponseCode::NoError => nsec1_nodata(qname, qtype, nsecs),
        ResponseCode::NXDomain => nsec1_nxdomain(qname, soa_name, nsecs),
        _ => ValidationResult::Bogus,
    }
}

/// True when the NSEC at `owner` with `next` covers `target` (owner < t < next),
/// honoring the wrap-around at the zone apex (last NSEC: owner > next).
fn nsec1_covers(owner: &Name, next: &Name, target: &Name) -> bool {
    if owner < next {
        owner < target && target < next
    } else {
        target > owner || target < next
    }
}

/// RFC 6840 §4.4 — a DS NODATA proof must come from the *parent* side of the
/// delegation. An NSEC/NSEC3 whose bitmap carries SOA is the child zone's own
/// apex record, and the child is not authoritative for its DS RRset, so it
/// cannot prove that RRset absent. Without this check a signed child could strip
/// the DS of its own delegation and downgrade itself to Insecure.
///
/// Note the converse is deliberately *not* required: a matching record without
/// the NS bit simply means the name is not a zone cut, which is a legitimate
/// "no DS here" for the intermediate labels the chain walk steps through.
fn wrong_side_of_delegation(mut type_bit_maps: impl Iterator<Item = RecordType>) -> bool {
    type_bit_maps.any(|t| t == RecordType::SOA)
}

fn nsec1_nodata(qname: &Name, qtype: RecordType, nsecs: &[VerifiedNsec<'_>]) -> ValidationResult {
    // Direct match: an NSEC owned by QNAME with QTYPE and CNAME absent.
    for n in nsecs {
        if n.owner != qname {
            continue;
        }
        // RFC 6840 §4.4 — see `nsec3_nodata`. Skipping rather than returning
        // also keeps this independent of record order: a child-side NSEC listed
        // ahead of a valid parent-side one must not decide the outcome.
        if qtype == RecordType::DS && wrong_side_of_delegation(n.data.type_bit_maps()) {
            continue;
        }
        let has_type = n.data.type_bit_maps().any(|t| t == qtype);
        let has_cname = n.data.type_bit_maps().any(|t| t == RecordType::CNAME);
        if has_type || has_cname {
            return ValidationResult::Bogus;
        }
        return ValidationResult::Secure;
    }
    // No NSEC matched the name — cannot prove this NODATA. Fail open.
    ValidationResult::Insecure
}

fn nsec1_nxdomain(qname: &Name, soa_name: &Name, nsecs: &[VerifiedNsec<'_>]) -> ValidationResult {
    // An NSEC must cover QNAME (proving the exact name does not exist).
    let covering = nsecs
        .iter()
        .find(|n| nsec1_covers(n.owner, n.data.next_domain_name(), qname));
    let Some(covering) = covering else {
        return ValidationResult::Bogus;
    };

    // Closest encloser = longest common ancestor of QNAME with the covering
    // NSEC's owner or its next name (RFC 7129 §5.5).
    let ce_owner = common_suffix(qname, covering.owner);
    let ce_next = common_suffix(qname, covering.data.next_domain_name());
    let closest = if ce_owner.num_labels() >= ce_next.num_labels() {
        ce_owner
    } else {
        ce_next
    };
    if closest.num_labels() < soa_name.num_labels() {
        return ValidationResult::Bogus;
    }

    // The wildcard at the closest encloser must be covered (proven absent).
    let Some(wildcard) = make_wildcard(&closest) else {
        return ValidationResult::Bogus;
    };
    let wildcard_covered = nsecs.iter().any(|n| {
        n.owner == &wildcard || nsec1_covers(n.owner, n.data.next_domain_name(), &wildcard)
    });
    if wildcard_covered {
        ValidationResult::Secure
    } else {
        ValidationResult::Bogus
    }
}

/// Longest common suffix (shared ancestor) of two names, by labels.
fn common_suffix(a: &Name, b: &Name) -> Name {
    let a_labels: Vec<&[u8]> = a.iter().collect();
    let b_labels: Vec<&[u8]> = b.iter().collect();
    let mut shared: Vec<&[u8]> = Vec::new();
    let mut ai = a_labels.len();
    let mut bi = b_labels.len();
    while ai > 0 && bi > 0 {
        ai -= 1;
        bi -= 1;
        if a_labels[ai].eq_ignore_ascii_case(b_labels[bi]) {
            shared.push(a_labels[ai]);
        } else {
            break;
        }
    }
    shared.reverse();
    Name::from_labels(shared).unwrap_or_else(|_| Name::root())
}

// ===================== Wildcard expansion (RFC 4035 §5.3.4) ================

/// Prove that a wildcard-expanded *positive* answer is legitimate: the exact
/// `qname` must be shown not to exist (otherwise the wildcard must not have been
/// applied). `wildcard_labels` is the RRSIG `num_labels` of the answer.
pub fn prove_wildcard_expansion(
    qname: &Name,
    wildcard_labels: u8,
    nsec3s: &[VerifiedNsec3<'_>],
    nsecs: &[VerifiedNsec<'_>],
) -> ValidationResult {
    if !nsec3s.is_empty() {
        let salt = nsec3s[0].data.salt();
        let iterations = nsec3s[0].data.iterations();
        if iterations > NSEC3_ITERATION_CAP {
            return ValidationResult::Insecure;
        }
        if qname.num_labels() <= wildcard_labels {
            return ValidationResult::Bogus;
        }
        // Next closer: ancestor of qname one label longer than the wildcard's
        // closest encloser; an NSEC3 must *cover* it.
        let next_closer = ancestor_with_labels(qname, wildcard_labels + 1);
        match nsec3_hash(&next_closer, salt, iterations) {
            Some((nc_raw, nc_label)) => match nsec3_find_covering(nsec3s, &nc_raw, &nc_label) {
                Some(_) => ValidationResult::Secure,
                None => ValidationResult::Bogus,
            },
            None => ValidationResult::Insecure,
        }
    } else if !nsecs.is_empty() {
        if nsecs
            .iter()
            .any(|n| nsec1_covers(n.owner, n.data.next_domain_name(), qname))
        {
            ValidationResult::Secure
        } else {
            ValidationResult::Bogus
        }
    } else {
        // Wildcard expansion claimed but no NSEC/NSEC3 records to justify it.
        ValidationResult::Bogus
    }
}

/// The suffix of `name` consisting of its rightmost `n` labels.
fn ancestor_with_labels(name: &Name, n: u8) -> Name {
    let labels: Vec<&[u8]> = name.iter().collect();
    let take = (n as usize).min(labels.len());
    let start = labels.len() - take;
    Name::from_labels(labels[start..].to_vec()).unwrap_or_else(|_| name.clone())
}
