//! Authenticated denial of existence (RFC 4035 §5.4, RFC 5155, RFC 6840, RFC 9276).
//!
//! Given the NSEC / NSEC3 records of a negative response's authority section —
//! already proven authentic by their RRSIGs — these routines decide whether the
//! denial (NXDOMAIN / NODATA) is actually proven for the queried name and type.
//!
//! Mapping to [`DnssecStatus`]:
//! * `Secure` — the denial is fully proven.
//! * `Insecure` — the proof points at an NSEC3 opt-out span (which may hide an
//!   unsigned delegation), or the NSEC3 iteration count is above the hardening
//!   cap; serve without AD.
//! * `Bogus` — anything else. The zone is signed, so a denial that is not
//!   proven is indistinguishable from a forged one.
//!
//! The matching logic follows the structure of unbound / hickory's validator but
//! is implemented here against the project's own chain-of-trust machinery.

use crate::dns::dnssec::types::DsDenial;
use data_encoding::BASE32_DNSSEC;
use ferrous_dns_domain::DnssecStatus;
use hickory_proto::dnssec::crypto::Digest;
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
pub fn prove_denial(
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
    soa_name: &Name,
    nsec3s: &[VerifiedNsec3<'_>],
    nsecs: &[VerifiedNsec<'_>],
) -> DnssecStatus {
    if !nsec3s.is_empty() {
        verify_nsec3(qname, qtype, rcode, soa_name, nsec3s)
    } else if !nsecs.is_empty() {
        verify_nsec1(qname, qtype, rcode, soa_name, nsecs)
    } else {
        // Signed zone, negative answer, but no denial records at all: stripped.
        DnssecStatus::Bogus
    }
}

/// Classifies the parent zone's answer to a DS query for `child` (RFC 4035
/// §5.2). `None` when the records prove nothing about that DS, or contradict
/// the empty answer — either way the walk cannot continue past `child`.
pub fn classify_ds_denial(
    child: &Name,
    rcode: ResponseCode,
    parent: &Name,
    nsec3s: &[VerifiedNsec3<'_>],
    nsecs: &[VerifiedNsec<'_>],
) -> Option<DsDenial> {
    match rcode {
        ResponseCode::NXDomain => {
            match prove_denial(child, RecordType::DS, rcode, parent, nsec3s, nsecs) {
                DnssecStatus::Secure => Some(DsDenial::Nonexistent),
                // Opt-out over the next closer, or an iteration count past the cap.
                DnssecStatus::Insecure => Some(DsDenial::InsecureDelegation),
                DnssecStatus::Bogus | DnssecStatus::Indeterminate => None,
            }
        }
        ResponseCode::NoError if !nsec3s.is_empty() => nsec3_ds_nodata(child, parent, nsec3s),
        ResponseCode::NoError => nsec1_ds_nodata(child, nsecs),
        _ => None,
    }
}

/// What a parent-side record owned by the DS query name proves.
fn ds_denial_at(has: impl Fn(RecordType) -> bool) -> Option<DsDenial> {
    if has(RecordType::DS) || has(RecordType::CNAME) {
        return None;
    }
    Some(if has(RecordType::NS) {
        DsDenial::InsecureDelegation
    } else {
        DsDenial::NotZoneCut
    })
}

/// RFC 6840 §4.4 — a DS proof must come from the *parent* side of the
/// delegation. An NSEC/NSEC3 whose bitmap carries SOA is the child zone's own
/// apex record, and the child is not authoritative for its DS RRset, so it
/// cannot prove that RRset absent. Without this check a signed child could strip
/// the DS of its own delegation and downgrade itself to Insecure.
fn wrong_side_of_delegation(mut type_bit_maps: impl Iterator<Item = RecordType>) -> bool {
    type_bit_maps.any(|t| t == RecordType::SOA)
}

/// NS without SOA: the parent's record at a zone cut. RFC 6840 §4.1 — it
/// proves nothing about names at or below the cut except the DS the parent
/// itself holds, because those names live in the child zone.
fn is_delegation(type_bit_maps: impl Iterator<Item = RecordType>) -> bool {
    let (mut ns, mut soa) = (false, false);
    for t in type_bit_maps {
        ns |= t == RecordType::NS;
        soa |= t == RecordType::SOA;
    }
    ns && !soa
}

/// RFC 5155 §8.2 parameter agreement plus the RFC 9276 iteration cap. `Err`
/// carries the verdict when the records cannot be used for a proof.
fn nsec3_params<'a>(nsec3s: &'a [VerifiedNsec3<'_>]) -> Result<(&'a [u8], u16), DnssecStatus> {
    let first = &nsec3s[0];
    let salt = first.data.salt();
    let iterations = first.data.iterations();
    if nsec3s.iter().any(|r| {
        r.data.hash_algorithm() != first.data.hash_algorithm()
            || r.data.salt() != salt
            || r.data.iterations() != iterations
    }) {
        return Err(DnssecStatus::Bogus);
    }
    if iterations > NSEC3_ITERATION_CAP {
        return Err(DnssecStatus::Insecure);
    }
    Ok((salt, iterations))
}

fn verify_nsec3(
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
    soa_name: &Name,
    nsec3s: &[VerifiedNsec3<'_>],
) -> DnssecStatus {
    let (salt, iterations) = match nsec3_params(nsec3s) {
        Ok(params) => params,
        Err(status) => return status,
    };
    match rcode {
        ResponseCode::NXDomain => nsec3_nxdomain(qname, soa_name, salt, iterations, nsec3s),
        ResponseCode::NoError => nsec3_nodata(qname, qtype, soa_name, salt, iterations, nsec3s),
        _ => DnssecStatus::Bogus,
    }
}

/// Hash `name` and return (raw digest, base32 label). `None` on hashing failure.
fn nsec3_hash(name: &Name, salt: &[u8], iterations: u16) -> Option<(Digest, Label)> {
    let digest = Nsec3HashAlgorithm::SHA1.hash(salt, name, iterations).ok()?;
    let raw = digest.as_ref();
    // SHA-1 is 20 bytes, 32 in base32; the stack buffer covers any digest up to 40.
    let mut base32 = [0u8; 64];
    let base32 = base32.get_mut(..BASE32_DNSSEC.encode_len(raw.len()))?;
    BASE32_DNSSEC.encode_mut(raw, base32);
    let label = Label::from_ascii(std::str::from_utf8(base32).ok()?).ok()?;
    Some((digest, label))
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

/// RFC 5155 §8.3 closest provable encloser of `qname`, with the NSEC3 that
/// covers its next closer name.
struct ClosestEncloser<'a> {
    encloser: Name,
    next_closer_cover: &'a VerifiedNsec3<'a>,
}

/// The closest provable encloser proof: the longest *proper* ancestor of
/// `qname` with a matching NSEC3, plus a covering NSEC3 for the next closer.
/// `None` when the records do not form that proof.
fn closest_encloser_proof<'a>(
    qname: &Name,
    soa_name: &Name,
    salt: &[u8],
    iterations: u16,
    nsec3s: &'a [VerifiedNsec3<'a>],
) -> Option<ClosestEncloser<'a>> {
    let candidates = encloser_candidates(qname, soa_name);
    for idx in 1..candidates.len() {
        let Some((_, ce_label)) = nsec3_hash(&candidates[idx], salt, iterations) else {
            continue;
        };
        let Some(ce) = nsec3_find_matching(nsec3s, &ce_label) else {
            continue;
        };
        // RFC 5155 §8.3: a delegation cannot be the closest encloser; names
        // below it belong to another zone.
        if is_delegation(ce.data.type_bit_maps()) {
            return None;
        }
        let (nc_raw, nc_label) = nsec3_hash(&candidates[idx - 1], salt, iterations)?;
        let next_closer_cover = nsec3_find_covering(nsec3s, nc_raw.as_ref(), &nc_label)?;
        return Some(ClosestEncloser {
            encloser: candidates[idx].clone(),
            next_closer_cover,
        });
    }
    None
}

/// RFC 5155 §8.4 — NXDOMAIN closest-encloser proof.
fn nsec3_nxdomain(
    qname: &Name,
    soa_name: &Name,
    salt: &[u8],
    iterations: u16,
    nsec3s: &[VerifiedNsec3<'_>],
) -> DnssecStatus {
    // NXDOMAIN must not carry a matching NSEC3 for the query name itself.
    if let Some((_, qlabel)) = nsec3_hash(qname, salt, iterations) {
        if nsec3_find_matching(nsec3s, &qlabel).is_some() {
            return DnssecStatus::Bogus;
        }
    }

    let Some(proof) = closest_encloser_proof(qname, soa_name, salt, iterations, nsec3s) else {
        return DnssecStatus::Bogus;
    };
    // Opt-out over the next closer → the (insecure) name may exist unsigned.
    if proof.next_closer_cover.data.opt_out() {
        return DnssecStatus::Insecure;
    }
    // Wildcard at the closest encloser must be covered (proven absent).
    let Some(wildcard) = make_wildcard(&proof.encloser) else {
        return DnssecStatus::Bogus;
    };
    let Some((wc_raw, wc_label)) = nsec3_hash(&wildcard, salt, iterations) else {
        return DnssecStatus::Bogus;
    };
    match nsec3_find_covering(nsec3s, wc_raw.as_ref(), &wc_label) {
        Some(_) => DnssecStatus::Secure,
        None => DnssecStatus::Bogus,
    }
}

/// RFC 5155 §8.5–8.7 — NODATA proofs.
fn nsec3_nodata(
    qname: &Name,
    qtype: RecordType,
    soa_name: &Name,
    salt: &[u8],
    iterations: u16,
    nsec3s: &[VerifiedNsec3<'_>],
) -> DnssecStatus {
    let Some((_, q_label)) = nsec3_hash(qname, salt, iterations) else {
        return DnssecStatus::Bogus;
    };

    // §8.5 / §8.6 — an NSEC3 matching QNAME with QTYPE and CNAME absent.
    if let Some(record) = nsec3_find_matching(nsec3s, &q_label) {
        // A child-side record cannot deny a DS (RFC 6840 §4.4), and a
        // parent-side delegation record cannot deny anything but the DS
        // (RFC 6840 §4.1). Either is unusable here; the remaining proofs decide.
        let usable = if qtype == RecordType::DS {
            !wrong_side_of_delegation(record.data.type_bit_maps())
        } else {
            !is_delegation(record.data.type_bit_maps())
        };
        if usable {
            let has_type = record.data.type_bit_maps().any(|t| t == qtype);
            let has_cname = record.data.type_bit_maps().any(|t| t == RecordType::CNAME);
            if has_type || has_cname {
                return DnssecStatus::Bogus;
            }
            return DnssecStatus::Secure;
        }
    }

    // Both remaining proofs start from the closest-encloser proof; build it
    // once, since each candidate costs an iterated SHA-1.
    let Some(proof) = closest_encloser_proof(qname, soa_name, salt, iterations, nsec3s) else {
        return DnssecStatus::Bogus;
    };

    // §8.7 — wildcard NODATA: closest-encloser proof for a servicing wildcard.
    if wildcard_nodata(&proof, qtype, salt, iterations, nsec3s) {
        return DnssecStatus::Secure;
    }

    // §8.6 — no matching record: only an opt-out span over the next closer,
    // which may hide an unsigned delegation, leaves the name unproven-but-
    // legitimate. Anything short of that is not a proof.
    if proof.next_closer_cover.data.opt_out() {
        DnssecStatus::Insecure
    } else {
        DnssecStatus::Bogus
    }
}

/// Wildcard NODATA (RFC 5155 §8.7): an NSEC3 matching the wildcard at the
/// closest encloser, without QTYPE or CNAME.
fn wildcard_nodata(
    proof: &ClosestEncloser<'_>,
    qtype: RecordType,
    salt: &[u8],
    iterations: u16,
    nsec3s: &[VerifiedNsec3<'_>],
) -> bool {
    let Some(wildcard) = make_wildcard(&proof.encloser) else {
        return false;
    };
    let Some((_, wc_label)) = nsec3_hash(&wildcard, salt, iterations) else {
        return false;
    };
    nsec3_find_matching(nsec3s, &wc_label).is_some_and(|record| {
        !record
            .data
            .type_bit_maps()
            .any(|t| t == qtype || t == RecordType::CNAME)
    })
}

/// DS NODATA over NSEC3: the parent-side record matching `child`, or an
/// opt-out span over it (RFC 5155 §8.6).
fn nsec3_ds_nodata(child: &Name, parent: &Name, nsec3s: &[VerifiedNsec3<'_>]) -> Option<DsDenial> {
    let (salt, iterations) = match nsec3_params(nsec3s) {
        Ok(params) => params,
        Err(DnssecStatus::Insecure) => return Some(DsDenial::InsecureDelegation),
        Err(_) => return None,
    };
    let (_, label) = nsec3_hash(child, salt, iterations)?;
    if let Some(record) = nsec3s
        .iter()
        .filter(|r| r.owner_label == label)
        .find(|r| !wrong_side_of_delegation(r.data.type_bit_maps()))
    {
        return ds_denial_at(|t| record.data.type_bit_maps().any(|b| b == t));
    }
    closest_encloser_proof(child, parent, salt, iterations, nsec3s)
        .filter(|proof| proof.next_closer_cover.data.opt_out())
        .map(|_| DsDenial::InsecureDelegation)
}

fn make_wildcard(name: &Name) -> Option<Name> {
    Name::new().append_label("*").ok()?.append_name(name).ok()
}

fn verify_nsec1(
    qname: &Name,
    qtype: RecordType,
    rcode: ResponseCode,
    soa_name: &Name,
    nsecs: &[VerifiedNsec<'_>],
) -> DnssecStatus {
    match rcode {
        ResponseCode::NoError => nsec1_nodata(qname, qtype, soa_name, nsecs),
        ResponseCode::NXDomain => nsec1_nxdomain(qname, soa_name, nsecs),
        _ => DnssecStatus::Bogus,
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

/// An NSEC covering `target` that may be used to deny it: not the parent's
/// record at a zone cut above `target` (RFC 6840 §4.1).
fn nsec1_usable_cover<'a, 'b>(
    nsecs: &'a [VerifiedNsec<'b>],
    target: &Name,
) -> Option<&'a VerifiedNsec<'b>> {
    nsecs.iter().find(|n| {
        nsec1_covers(n.owner, n.data.next_domain_name(), target)
            && !(n.owner.zone_of(target) && is_delegation(n.data.type_bit_maps()))
    })
}

/// RFC 4035 §3.1.3.2 — an empty non-terminal has no NSEC of its own; the NSEC
/// covering it has a next name below it.
fn nsec1_empty_non_terminal(qname: &Name, nsecs: &[VerifiedNsec<'_>]) -> bool {
    nsec1_usable_cover(nsecs, qname).is_some_and(|n| {
        let next = n.data.next_domain_name();
        next.num_labels() > qname.num_labels() && qname.zone_of(next)
    })
}

fn nsec1_nodata(
    qname: &Name,
    qtype: RecordType,
    soa_name: &Name,
    nsecs: &[VerifiedNsec<'_>],
) -> DnssecStatus {
    // Direct match: an NSEC owned by QNAME with QTYPE and CNAME absent.
    for n in nsecs {
        if n.owner != qname {
            continue;
        }
        // Same usability rules as `nsec3_nodata`. Skipping rather than
        // returning keeps this independent of record order: an unusable record
        // listed ahead of a valid one must not decide the outcome.
        let unusable = if qtype == RecordType::DS {
            wrong_side_of_delegation(n.data.type_bit_maps())
        } else {
            is_delegation(n.data.type_bit_maps())
        };
        if unusable {
            continue;
        }
        let has_type = n.data.type_bit_maps().any(|t| t == qtype);
        let has_cname = n.data.type_bit_maps().any(|t| t == RecordType::CNAME);
        if has_type || has_cname {
            return DnssecStatus::Bogus;
        }
        return DnssecStatus::Secure;
    }

    if nsec1_empty_non_terminal(qname, nsecs)
        || nsec1_wildcard_nodata(qname, qtype, soa_name, nsecs)
    {
        return DnssecStatus::Secure;
    }
    DnssecStatus::Bogus
}

/// RFC 4035 §3.1.3.4 — wildcard NODATA: QNAME is covered (does not exist) and
/// the NSEC of the wildcard at its closest encloser lacks QTYPE and CNAME.
fn nsec1_wildcard_nodata(
    qname: &Name,
    qtype: RecordType,
    soa_name: &Name,
    nsecs: &[VerifiedNsec<'_>],
) -> bool {
    let Some(covering) = nsec1_usable_cover(nsecs, qname) else {
        return false;
    };
    let closest = nsec1_closest_encloser(qname, covering);
    if closest.num_labels() < soa_name.num_labels() {
        return false;
    }
    let Some(wildcard) = make_wildcard(&closest) else {
        return false;
    };
    nsecs.iter().any(|n| {
        n.owner == &wildcard
            && !n
                .data
                .type_bit_maps()
                .any(|t| t == qtype || t == RecordType::CNAME)
    })
}

/// Closest encloser = longest common ancestor of QNAME with the covering
/// NSEC's owner or its next name (RFC 7129 §5.5).
fn nsec1_closest_encloser(qname: &Name, covering: &VerifiedNsec<'_>) -> Name {
    let ce_owner = common_suffix(qname, covering.owner);
    let ce_next = common_suffix(qname, covering.data.next_domain_name());
    if ce_owner.num_labels() >= ce_next.num_labels() {
        ce_owner
    } else {
        ce_next
    }
}

fn nsec1_nxdomain(qname: &Name, soa_name: &Name, nsecs: &[VerifiedNsec<'_>]) -> DnssecStatus {
    // An NSEC must cover QNAME (proving the exact name does not exist).
    let Some(covering) = nsec1_usable_cover(nsecs, qname) else {
        return DnssecStatus::Bogus;
    };
    let closest = nsec1_closest_encloser(qname, covering);
    if closest.num_labels() < soa_name.num_labels() {
        return DnssecStatus::Bogus;
    }

    // The wildcard at the closest encloser must be covered (proven absent).
    let Some(wildcard) = make_wildcard(&closest) else {
        return DnssecStatus::Bogus;
    };
    // Covered, not matched: an NSEC owned by the wildcard proves it exists, in
    // which case the answer should have been synthesized from it.
    if nsec1_usable_cover(nsecs, &wildcard).is_some() {
        DnssecStatus::Secure
    } else {
        DnssecStatus::Bogus
    }
}

/// DS NODATA over NSEC: the parent-side record owned by `child`, or proof that
/// `child` is an empty non-terminal of the parent zone.
fn nsec1_ds_nodata(child: &Name, nsecs: &[VerifiedNsec<'_>]) -> Option<DsDenial> {
    if let Some(n) = nsecs
        .iter()
        .filter(|n| n.owner == child)
        .find(|n| !wrong_side_of_delegation(n.data.type_bit_maps()))
    {
        return ds_denial_at(|t| n.data.type_bit_maps().any(|b| b == t));
    }
    nsec1_empty_non_terminal(child, nsecs).then_some(DsDenial::NotZoneCut)
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

/// Prove that a wildcard-expanded *positive* answer is legitimate: the exact
/// `qname` must be shown not to exist (otherwise the wildcard must not have been
/// applied). `wildcard_labels` is the RRSIG `num_labels` of the answer.
pub fn prove_wildcard_expansion(
    qname: &Name,
    wildcard_labels: u8,
    nsec3s: &[VerifiedNsec3<'_>],
    nsecs: &[VerifiedNsec<'_>],
) -> DnssecStatus {
    if !nsec3s.is_empty() {
        let (salt, iterations) = match nsec3_params(nsec3s) {
            Ok(params) => params,
            Err(status) => return status,
        };
        if qname.num_labels() <= wildcard_labels {
            return DnssecStatus::Bogus;
        }
        // Next closer: ancestor of qname one label longer than the wildcard's
        // closest encloser; an NSEC3 must *cover* it.
        let next_closer = ancestor_with_labels(qname, wildcard_labels + 1);
        match nsec3_hash(&next_closer, salt, iterations) {
            Some((nc_raw, nc_label)) => {
                match nsec3_find_covering(nsec3s, nc_raw.as_ref(), &nc_label) {
                    Some(_) => DnssecStatus::Secure,
                    None => DnssecStatus::Bogus,
                }
            }
            None => DnssecStatus::Bogus,
        }
    } else if nsec1_usable_cover(nsecs, qname).is_some() {
        DnssecStatus::Secure
    } else {
        // Wildcard expansion claimed but no NSEC/NSEC3 records to justify it.
        DnssecStatus::Bogus
    }
}

/// The suffix of `name` consisting of its rightmost `n` labels.
fn ancestor_with_labels(name: &Name, n: u8) -> Name {
    let labels: Vec<&[u8]> = name.iter().collect();
    let take = (n as usize).min(labels.len());
    let start = labels.len() - take;
    Name::from_labels(labels[start..].to_vec()).unwrap_or_else(|_| name.clone())
}
