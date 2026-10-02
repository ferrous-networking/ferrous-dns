use super::cache::DnssecCache;
use super::trust_anchor::TrustAnchorStore;
use super::types::DnskeyRecord;
use super::validation::authority::{self as auth_check, now_secs, to_fqdn};
use super::validation::denial::{prove_denial, prove_wildcard_expansion};
use super::validation::{ChainFailure, ChainTrust, ChainVerifier};
use crate::dns::forwarding::record_type_map::RecordTypeMapper;
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DnssecStatus, DomainError, RecordType};
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RData, Record};
use std::sync::Arc;
use tracing::{debug, warn};

/// Upper bound on distinct chain walks one answer may trigger. Every RRset
/// anchors a walk (at its signer, or at its owner when unsigned) and each walk
/// costs per-label DS + DNSKEY fetches, so a crafted answer naming many
/// distinct zones would multiply upstream queries. A legitimate answer — even
/// a long cross-zone CNAME chain — needs only a few.
const MAX_CHAIN_WALKS: usize = 8;

/// A chain walk done for this answer, memoized so each name is walked once.
struct Walk<'a> {
    anchor: &'a Name,
    /// `anchor` in presentation form, as handed to the walk.
    walked: String,
    trust: Result<ChainTrust, ChainFailure>,
}

impl Walk<'_> {
    /// The walk ended in a signed zone whose apex is the walked name itself.
    fn secure_apex(&self) -> Option<&str> {
        match &self.trust {
            Ok(ChainTrust::Secure { zone }) if zone.eq_ignore_ascii_case(&self.walked) => {
                Some(zone)
            }
            _ => None,
        }
    }
}

/// One answer RRset and the zones that claim to have signed it, borrowed from
/// the message.
struct AnswerRrset<'a> {
    owner: &'a Name,
    rtype: hickory_proto::rr::RecordType,
    records: Vec<&'a Record>,
    /// Distinct signers of the covering RRSIGs, restricted to those that
    /// enclose the owner (RFC 4035 §5.3.1). Empty: the RRset is unsigned.
    signers: Vec<&'a Name>,
}

impl<'a> AnswerRrset<'a> {
    /// The name whose chain decides this RRset's fate.
    fn walk_anchors(&self) -> &[&'a Name] {
        if self.signers.is_empty() {
            std::slice::from_ref(&self.owner)
        } else {
            &self.signers
        }
    }
}

fn covering_rrsigs<'a>(
    owner: &'a Name,
    rtype: hickory_proto::rr::RecordType,
    answers: &'a [Record],
) -> impl Iterator<Item = &'a hickory_proto::dnssec::rdata::RRSIG> + 'a {
    answers.iter().filter_map(move |record| match &record.data {
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
            if &record.name == owner && rrsig.input().type_covered == rtype =>
        {
            Some(rrsig)
        }
        _ => None,
    })
}

fn group_rrsets(answers: &[Record]) -> Vec<AnswerRrset<'_>> {
    let mut rrsets: Vec<AnswerRrset<'_>> = Vec::new();
    for record in answers {
        if matches!(record.data, RData::DNSSEC(DNSSECRData::RRSIG(_))) {
            continue;
        }
        let rtype = record.record_type();
        match rrsets
            .iter_mut()
            .find(|r| r.owner == &record.name && r.rtype == rtype)
        {
            Some(rrset) => rrset.records.push(record),
            None => rrsets.push(AnswerRrset {
                owner: &record.name,
                rtype,
                records: vec![record],
                signers: Vec::new(),
            }),
        }
    }
    for rrset in &mut rrsets {
        for rrsig in covering_rrsigs(rrset.owner, rrset.rtype, answers) {
            let signer = &rrsig.input().signer_name;
            if auth_check::name_encloses(signer, rrset.owner) && !rrset.signers.contains(&signer) {
                rrset.signers.push(signer);
            }
        }
    }
    rrsets
}

/// The most severe of two outcomes: Bogus > Indeterminate > Insecure > Secure.
fn most_severe(a: DnssecStatus, b: DnssecStatus) -> DnssecStatus {
    match (a, b) {
        (DnssecStatus::Bogus, _) | (_, DnssecStatus::Bogus) => DnssecStatus::Bogus,
        (DnssecStatus::Indeterminate, _) | (_, DnssecStatus::Indeterminate) => {
            DnssecStatus::Indeterminate
        }
        (DnssecStatus::Insecure, _) | (_, DnssecStatus::Insecure) => DnssecStatus::Insecure,
        (DnssecStatus::Secure, DnssecStatus::Secure) => DnssecStatus::Secure,
    }
}

/// Key lookup that only answers for `zone`, so a record signed by any other
/// zone — even one this validation also proved — cannot vouch for it.
fn keys_of(
    zone: &Name,
    keys: Option<Arc<[DnskeyRecord]>>,
) -> impl Fn(&Name) -> Option<Arc<[DnskeyRecord]>> + '_ {
    move |signer: &Name| if signer == zone { keys.clone() } else { None }
}

pub struct DnssecValidator {
    pool_manager: Arc<PoolManager>,

    chain_verifier: ChainVerifier,

    timeout_ms: u64,
}

impl DnssecValidator {
    pub fn new(
        pool_manager: Arc<PoolManager>,
        trust_store: TrustAnchorStore,
        dnssec_cache: Arc<DnssecCache>,
        timeout_ms: u64,
    ) -> Self {
        let chain_verifier =
            ChainVerifier::new(pool_manager.clone(), trust_store, dnssec_cache, timeout_ms);

        Self {
            pool_manager,
            chain_verifier,
            timeout_ms,
        }
    }

    pub async fn validate_query(
        &mut self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<DnssecStatus, DomainError> {
        debug!(
            domain = %domain,
            record_type = ?record_type,
            "Starting DNSSEC validation"
        );

        let start = std::time::Instant::now();

        let domain_arc: Arc<str> = Arc::from(domain);
        let upstream_result = self
            .pool_manager
            .query(&domain_arc, &record_type, self.timeout_ms, true)
            .await?;

        debug!(
            domain = %domain,
            server = %upstream_result.server_display,
            latency_ms = upstream_result.latency_ms,
            "DNS query completed"
        );

        let validation_status = self
            .validate_message(domain, record_type, &upstream_result.response.message)
            .await;

        debug!(
            domain = %domain,
            status = %validation_status.as_str(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "DNSSEC validation completed"
        );

        Ok(validation_status)
    }

    pub async fn validate_with_message(
        &mut self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> DnssecStatus {
        debug!(
            domain = %domain,
            record_type = ?record_type,
            "Starting DNSSEC validation (pre-fetched response)"
        );

        let start = std::time::Instant::now();

        let validation_status = self.validate_message(domain, record_type, message).await;

        debug!(
            domain = %domain,
            status = %validation_status.as_str(),
            elapsed_ms = start.elapsed().as_millis() as u64,
            "DNSSEC validation completed (pre-fetched)"
        );

        validation_status
    }

    /// Runs full validation over an already-fetched message: every answer
    /// RRset is anchored to the chain of trust on its own; empty answers
    /// (NXDOMAIN / NODATA) go through authenticated denial of existence.
    async fn validate_message(
        &mut self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> DnssecStatus {
        self.chain_verifier.clear_established_keys();
        if message.answers.is_empty() {
            return self.validate_negative(domain, record_type, message).await;
        }
        self.validate_positive(domain, &message.answers, &message.authorities)
            .await
    }

    async fn validate_positive(
        &mut self,
        domain: &str,
        answers: &[Record],
        authorities: &[Record],
    ) -> DnssecStatus {
        let rrsets = group_rrsets(answers);
        if rrsets.is_empty() {
            warn!(domain = %domain, "answer section holds only RRSIGs");
            return DnssecStatus::Bogus;
        }

        let mut anchors: Vec<&Name> = Vec::new();
        for &anchor in rrsets.iter().flat_map(AnswerRrset::walk_anchors) {
            if !anchors.contains(&anchor) {
                anchors.push(anchor);
            }
        }
        if anchors.len() > MAX_CHAIN_WALKS {
            warn!(
                domain = %domain,
                walks = anchors.len(),
                "answer needs too many chain walks; refusing (possible amplification)"
            );
            return DnssecStatus::Bogus;
        }

        let mut walks: Vec<Walk<'_>> = Vec::with_capacity(anchors.len());
        let mut status = DnssecStatus::Secure;
        for rrset in &rrsets {
            let rrset_status = self
                .rrset_status(rrset, &mut walks, answers, authorities)
                .await;
            status = most_severe(status, rrset_status);
            // Bogus dominates every other outcome: stop and save the queries.
            if status == DnssecStatus::Bogus {
                break;
            }
        }
        status
    }

    async fn trust<'a, 'w>(
        &mut self,
        walks: &'w mut Vec<Walk<'a>>,
        anchor: &'a Name,
    ) -> &'w Walk<'a> {
        if let Some(done) = walks.iter().position(|walk| walk.anchor == anchor) {
            return &walks[done];
        }
        let walked = anchor.to_string();
        let trust = self.chain_verifier.verify_chain(&walked).await;
        let index = walks.len();
        walks.push(Walk {
            anchor,
            walked,
            trust,
        });
        &walks[index]
    }

    async fn rrset_status<'a>(
        &mut self,
        rrset: &AnswerRrset<'a>,
        walks: &mut Vec<Walk<'a>>,
        answers: &[Record],
        authorities: &[Record],
    ) -> DnssecStatus {
        if rrset.signers.is_empty() {
            return match &self.trust(walks, rrset.owner).await.trust {
                Ok(ChainTrust::Insecure) => DnssecStatus::Insecure,
                Ok(ChainTrust::Secure { zone }) => {
                    warn!(
                        owner = %rrset.owner,
                        rtype = ?rrset.rtype,
                        zone = %zone,
                        "unsigned RRset inside a signed zone"
                    );
                    DnssecStatus::Bogus
                }
                Err(failure) => failure.status(),
            };
        }

        let mut outcome = DnssecStatus::Secure;
        for &signer in &rrset.signers {
            let walk = self.trust(walks, signer).await;
            let status = match (&walk.trust, walk.secure_apex()) {
                (_, Some(zone)) => {
                    self.signed_rrset_status(rrset, signer, zone, answers, authorities)
                }
                (Ok(ChainTrust::Secure { zone }), None) => {
                    warn!(owner = %rrset.owner, signer = %signer, zone = %zone, "RRSIG signer is not a zone apex");
                    DnssecStatus::Bogus
                }
                (Ok(ChainTrust::Insecure), None) => DnssecStatus::Insecure,
                (Err(failure), None) => failure.status(),
            };
            if status == DnssecStatus::Secure {
                return status;
            }
            outcome = most_severe(outcome, status);
        }
        outcome
    }

    /// A signed RRset whose signer the walk proved to be the secure zone
    /// `zone`: the signature must verify under that zone's keys, and a wildcard
    /// expansion must come with proof that the exact owner does not exist.
    fn signed_rrset_status(
        &self,
        rrset: &AnswerRrset<'_>,
        signer: &Name,
        zone: &str,
        answers: &[Record],
        authorities: &[Record],
    ) -> DnssecStatus {
        let lookup = keys_of(signer, self.chain_verifier.get_zone_keys(zone).cloned());
        let now = now_secs();
        if !auth_check::rrset_is_authentic(
            rrset.owner,
            rrset.rtype,
            &rrset.records,
            answers,
            now,
            &lookup,
        ) {
            warn!(owner = %rrset.owner, rtype = ?rrset.rtype, zone = %zone, "RRset not covered by a valid RRSIG");
            return DnssecStatus::Bogus;
        }

        // RFC 4035 §5.3.4: an RRSIG label count below the owner's marks a
        // wildcard expansion.
        let owner_labels = rrset.owner.num_labels();
        let Some(wildcard_labels) = covering_rrsigs(rrset.owner, rrset.rtype, answers)
            .map(|rrsig| rrsig.input().num_labels)
            .filter(|labels| *labels < owner_labels)
            .min()
        else {
            return DnssecStatus::Secure;
        };
        let (nsec3s, nsecs) = auth_check::collect_verified_denial(authorities, now, &lookup);
        prove_wildcard_expansion(rrset.owner, wildcard_labels, &nsec3s, &nsecs)
    }

    /// Validates a negative response: a signed denial must come from the zone
    /// that encloses the name and prove it; an unsigned one is only acceptable
    /// below a proven-insecure delegation.
    async fn validate_negative(
        &mut self,
        domain: &str,
        record_type: RecordType,
        message: &hickory_proto::op::Message,
    ) -> DnssecStatus {
        let Some(signer) = Self::extract_signer_zone(&message.authorities) else {
            return match self.chain_verifier.verify_chain(domain).await {
                Ok(ChainTrust::Insecure) => DnssecStatus::Insecure,
                Ok(ChainTrust::Secure { zone }) => {
                    warn!(domain = %domain, zone = %zone, "unsigned negative answer from a signed zone");
                    DnssecStatus::Bogus
                }
                Err(failure) => failure.status(),
            };
        };

        // The authority's signer zone must enclose the queried name. Otherwise a
        // validly-signed denial from an unrelated zone the attacker controls
        // could be presented as a proof about `domain`.
        let Some(qname) = to_fqdn(domain) else {
            return DnssecStatus::Bogus;
        };
        if !auth_check::name_encloses(signer, &qname) {
            warn!(
                domain = %domain,
                zone = %signer,
                "negative-answer signer zone does not enclose the queried name"
            );
            return DnssecStatus::Bogus;
        }

        let walked = signer.to_string();
        match self.chain_verifier.verify_chain(&walked).await {
            Ok(ChainTrust::Secure { zone }) if zone.eq_ignore_ascii_case(&walked) => self
                .validate_denial(
                    &qname,
                    record_type,
                    message.response_code,
                    signer,
                    &zone,
                    &message.authorities,
                ),
            Ok(ChainTrust::Secure { zone }) => {
                warn!(domain = %domain, signer = %signer, zone = %zone, "denial signer is not a zone apex");
                DnssecStatus::Bogus
            }
            Ok(ChainTrust::Insecure) => DnssecStatus::Insecure,
            Err(failure) => failure.status(),
        }
    }

    fn extract_signer_zone(authority: &[Record]) -> Option<&Name> {
        authority.iter().find_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
                if rrsig.input().type_covered != hickory_proto::rr::RecordType::DNSKEY =>
            {
                Some(&rrsig.input().signer_name)
            }
            _ => None,
        })
    }

    /// Validates an authenticated denial of existence (NXDOMAIN / NODATA) using
    /// the NSEC/NSEC3 records `zone` signed in the authority section.
    fn validate_denial(
        &self,
        qname: &Name,
        qtype: RecordType,
        rcode: ResponseCode,
        soa_name: &Name,
        zone: &str,
        authority: &[Record],
    ) -> DnssecStatus {
        let lookup = keys_of(soa_name, self.chain_verifier.get_zone_keys(zone).cloned());
        let (nsec3s, nsecs) = auth_check::collect_verified_denial(authority, now_secs(), &lookup);

        let result = prove_denial(
            qname,
            RecordTypeMapper::to_hickory(&qtype),
            rcode,
            soa_name,
            &nsec3s,
            &nsecs,
        );
        debug!(
            domain = %qname,
            zone = %zone,
            ?rcode,
            nsec3 = nsec3s.len(),
            nsec = nsecs.len(),
            status = %result.as_str(),
            "denial of existence validated"
        );
        result
    }
}
