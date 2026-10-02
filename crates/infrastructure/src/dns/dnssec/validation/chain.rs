use super::authority::{self as auth_check, now_secs, to_fqdn};
use super::denial::classify_ds_denial;
use crate::dns::dnssec::cache::DnssecCache;
use crate::dns::dnssec::crypto;
use crate::dns::dnssec::trust_anchor::TrustAnchorStore;
use crate::dns::dnssec::types::{DnskeyRecord, DsDenial, DsLookup, DsRecord};
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DnssecStatus, DomainError, RecordType};
use hickory_proto::dnssec::rdata::{DNSSECRData, RRSIG};
use hickory_proto::dnssec::PublicKey;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RData, Record, RecordType as HRecordType};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

/// Whether an error reflects an inability to reach the upstream (so we could
/// not validate) rather than forged or contradictory data.
fn is_transient_error(e: &DomainError) -> bool {
    matches!(
        e,
        DomainError::TransportAllServersUnreachable
            | DomainError::TransportNoHealthyServers
            | DomainError::QueryTimeout
            | DomainError::TransportTimeout { .. }
            | DomainError::TransportConnectionRefused { .. }
            | DomainError::TransportConnectionReset { .. }
            | DomainError::IoError(_)
    )
}

/// Ceiling on how long a *proven* absence of DS is cached. The authority SOA
/// can advertise a negative TTL of days; capping it bounds how long a delegation
/// stays pinned to Insecure after the zone is signed.
const MAX_NEGATIVE_DS_TTL: u32 = 3600;

/// Where the chain of trust from the root ends for a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainTrust {
    /// `zone` is the deepest signed zone enclosing the name; its keys are
    /// established for the current validation.
    Secure { zone: String },
    /// The parent's signed denial proves an unsigned delegation at or above
    /// the name.
    Insecure,
}

/// Why the chain of trust could not be established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainFailure {
    /// Forged, stripped, or contradictory data.
    Bogus,
    /// The records needed could not be fetched.
    Indeterminate,
}

impl ChainFailure {
    fn of(error: &DomainError) -> Self {
        if is_transient_error(error) {
            Self::Indeterminate
        } else {
            Self::Bogus
        }
    }

    pub fn status(self) -> DnssecStatus {
        match self {
            Self::Bogus => DnssecStatus::Bogus,
            Self::Indeterminate => DnssecStatus::Indeterminate,
        }
    }
}

/// Outcome of one walk step, from an established zone to a child name.
enum Step {
    /// The child is a signed zone; its keys are now established.
    SecureCut,
    /// The parent proved there is no DS at the child.
    NoDs(DsDenial),
}

struct DnskeyQueryResult {
    keys: Arc<[DnskeyRecord]>,
    /// Answer section of a fresh response, moved out of it: the DNSKEY RRset
    /// and its self-signature. Empty on a cache hit.
    answers: Vec<Record>,
    /// True when the keys came from the DNSKEY cache (already validated on the
    /// original fetch) rather than a fresh upstream response that still needs
    /// its self-signature checked.
    from_cache: bool,
    /// TTL to cache the validated key set under, once validation succeeds.
    ttl: u32,
}

/// An upstream DS answer that has not been authenticated yet.
struct FreshDs {
    /// DS records usable for validation (SHA-1 digests dropped per RFC 8624).
    records: Vec<DsRecord>,
    /// Answer section, moved out of the response: the *complete* DS RRset
    /// (SHA-1 entries included, since the RRSIG covers them) and its RRSIGs.
    answers: Vec<Record>,
    /// TTL to cache the authenticated DS set under.
    ttl: u32,
    /// Authority section, verbatim: the NSEC/NSEC3 (and RRSIGs) that must
    /// prove an empty answer.
    authority: Vec<Record>,
    /// Negative-caching TTL from the authority SOA (RFC 2308).
    negative_ttl: Option<u32>,
    /// Picks the denial proof shape (NODATA vs NXDOMAIN).
    rcode: ResponseCode,
}

fn rrset_of(answers: &[Record], rtype: HRecordType) -> impl Iterator<Item = &Record> {
    answers.iter().filter(move |r| r.record_type() == rtype)
}

fn rrsigs_covering(answers: &[Record], rtype: HRecordType) -> impl Iterator<Item = &RRSIG> {
    answers.iter().filter_map(move |r| match &r.data {
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) if rrsig.input().type_covered == rtype => {
            Some(rrsig)
        }
        _ => None,
    })
}

/// True when an RRSIG in `answers` verifies the `rtype` RRset there, owned by
/// `owner`, against one of `keys`.
fn any_rrsig_verifies(
    answers: &[Record],
    rtype: HRecordType,
    keys: &[impl std::borrow::Borrow<DnskeyRecord>],
    owner: &Name,
    now: u32,
) -> bool {
    rrsigs_covering(answers, rtype).any(|rrsig| {
        match crypto::rrsig_verifies(rrsig, keys, owner, rrset_of(answers, rtype), now) {
            Ok(verified) => verified,
            Err(e) => {
                warn!(owner = %owner, error = %e, "RRSIG verification error");
                false
            }
        }
    })
}

pub struct ChainVerifier {
    pool_manager: Arc<PoolManager>,
    trust_store: TrustAnchorStore,

    /// Keys of the zones proven secure during the current validation.
    validated_keys: HashMap<String, Arc<[DnskeyRecord]>>,

    dnssec_cache: Arc<DnssecCache>,

    /// Upstream timeout for the DS/DNSKEY lookups of the walk.
    timeout_ms: u64,
}

impl ChainVerifier {
    pub fn new(
        pool_manager: Arc<PoolManager>,
        trust_store: TrustAnchorStore,
        dnssec_cache: Arc<DnssecCache>,
        timeout_ms: u64,
    ) -> Self {
        Self {
            pool_manager,
            trust_store,
            validated_keys: HashMap::new(),
            dnssec_cache,
            timeout_ms,
        }
    }

    /// Forgets the zone keys of earlier validations, so key lookups only see
    /// zones this validation proved itself. Cheap: re-walks hit the DNSKEY cache.
    pub fn clear_established_keys(&mut self) {
        self.validated_keys.clear();
    }

    /// Walks from the root towards `name`, one label at a time, and reports
    /// where the chain of trust ends. A label without a DS is only passed when
    /// the zone above it *proves* the absence; the proof also says whether the
    /// label is an unsigned delegation (stop: Insecure), a name inside the same
    /// zone (keep walking under the same keys), or nonexistent (stop: the
    /// zone above encloses `name`).
    pub async fn verify_chain(&mut self, name: &str) -> Result<ChainTrust, ChainFailure> {
        debug!(name = %name, "Starting DNSSEC chain verification");

        if !self.trust_store.has_anchor_for(".") {
            warn!("No root trust anchor configured");
            return Err(ChainFailure::Indeterminate);
        }

        // Turn the configured KSK trust anchors into the full validated root
        // DNSKEY RRset (KSK + ZSK). The bare anchor KSK is not enough: the DS
        // RRset of each TLD is signed by the root *ZSK*. Done on every walk —
        // it is cache-backed, so it stays cheap while still honouring the
        // DNSKEY TTL and root key rollover.
        if let Err(e) = self.bootstrap_root_keys().await {
            warn!(error = %e, "Root key bootstrap failed");
            return Err(ChainFailure::of(&e));
        }

        let fqdn: Cow<'_, str> = if name.ends_with('.') {
            Cow::Borrowed(name)
        } else {
            Cow::Owned(format!("{name}."))
        };
        let mut zone = ".";
        for child in descending_suffixes(&fqdn) {
            match self.step(zone, child).await {
                Ok(Step::SecureCut) => zone = child,
                Ok(Step::NoDs(DsDenial::NotZoneCut)) => {}
                Ok(Step::NoDs(DsDenial::Nonexistent)) => break,
                Ok(Step::NoDs(DsDenial::InsecureDelegation)) => {
                    debug!(zone = %zone, child = %child, "Proven insecure delegation");
                    return Ok(ChainTrust::Insecure);
                }
                Err(e) => {
                    warn!(zone = %zone, child = %child, error = %e, "Chain of trust broken");
                    return Err(ChainFailure::of(&e));
                }
            }
        }

        debug!(name = %name, zone = %zone, "Chain of trust validated");
        Ok(ChainTrust::Secure {
            zone: zone.to_owned(),
        })
    }

    async fn step(&mut self, zone: &str, child: &str) -> Result<Step, DomainError> {
        // A cached DS answer settles the step on its own; only a cold lookup
        // fetches DNSKEY alongside it, betting on a secure cut to save an RTT.
        // Fetching it unconditionally would cost an upstream query on every
        // walk through an unsigned delegation, whose missing keys never cache.
        let (lookup, prefetched_dnskey) = match self.dnssec_cache.get_ds(child) {
            Some(lookup) => (lookup, None),
            None => {
                let (fresh, dnskey) = tokio::join!(
                    Self::fetch_ds(&self.pool_manager, child, self.timeout_ms),
                    Self::fetch_dnskey(
                        &self.dnssec_cache,
                        &self.pool_manager,
                        child,
                        self.timeout_ms
                    ),
                );
                (self.authenticate_ds(zone, child, fresh?)?, Some(dnskey))
            }
        };
        let ds_records = match lookup {
            DsLookup::Absent(denial) => return Ok(Step::NoDs(denial)),
            DsLookup::Present(records) => records,
        };

        // RFC 6840 §5.2: the DS RRset's algorithm field names the algorithm the
        // child zone signs with. If this build implements none of the algorithms
        // in the parent-authenticated DS RRset (or the delegation publishes only
        // SHA-1 digests, RFC 8624), there is no usable authentication path into
        // the child — it MUST be treated as Insecure, exactly as a proven
        // missing DS, NOT Bogus.
        if !ds_records
            .iter()
            .any(|ds| crypto::is_supported_algorithm(ds.algorithm))
        {
            debug!(child = %child, "DS RRset has no usable algorithm; treating child as insecure");
            return Ok(Step::NoDs(DsDenial::InsecureDelegation));
        }

        let dnskey_result = match prefetched_dnskey {
            Some(result) => result?,
            None => {
                Self::fetch_dnskey(
                    &self.dnssec_cache,
                    &self.pool_manager,
                    child,
                    self.timeout_ms,
                )
                .await?
            }
        };

        if dnskey_result.keys.is_empty() {
            warn!(domain = %child, "No DNSKEY records found");
            return Err(DomainError::InvalidDnsResponse(
                "No DNSKEY records found".into(),
            ));
        }

        let ds_matches = |key: &&DnskeyRecord| {
            ds_records
                .iter()
                .any(|ds| match crypto::verify_ds(ds, key, child) {
                    Ok(matched) => matched,
                    Err(e) => {
                        warn!(domain = %child, error = %e, "DS verification error");
                        false
                    }
                })
        };

        if dnskey_result.from_cache {
            // Cached keys passed the self-signature check when they were stored;
            // the DS, possibly re-fetched since, must still vouch for one of them.
            if !dnskey_result.keys.iter().any(|key| ds_matches(&key)) {
                warn!(domain = %child, "No cached DNSKEY matches the DS RRset");
                return Err(DomainError::InvalidDnsResponse(
                    "No matching DNSKEY for DS".into(),
                ));
            }
        } else {
            let anchored: Vec<&DnskeyRecord> =
                dnskey_result.keys.iter().filter(ds_matches).collect();
            if anchored.is_empty() {
                warn!(domain = %child, "No DNSKEY matched any DS record");
                return Err(DomainError::InvalidDnsResponse(
                    "No matching DNSKEY for DS".into(),
                ));
            }

            // RFC 4035 §5.2: before *any* key in the DNSKEY RRset is trusted, the
            // RRset must be validated with a key that a DS RR refers to. Trusting
            // every returned key without this check would let an on-path attacker
            // inject a rogue ZSK (with the DNSKEY RRSIGs stripped) and have answers
            // it signs accepted as Secure. Cached keys are exempt: the cache is only
            // populated below, after this check.
            let owner = to_fqdn(child).ok_or_else(|| {
                DomainError::InvalidDnsResponse(format!("unparseable DNSKEY owner {child}"))
            })?;
            if !any_rrsig_verifies(
                &dnskey_result.answers,
                HRecordType::DNSKEY,
                &anchored,
                &owner,
                now_secs(),
            ) {
                warn!(domain = %child, "DNSKEY RRset not self-signed by a DS-matched key");
                return Err(DomainError::InvalidDnsResponse(
                    "DNSKEY RRSIG verification failed".into(),
                ));
            }

            self.dnssec_cache.cache_dnskey(
                child,
                Arc::clone(&dnskey_result.keys),
                dnskey_result.ttl,
            );
        }

        self.validated_keys
            .insert(child.to_string(), dnskey_result.keys);

        Ok(Step::SecureCut)
    }

    /// Authenticates a fresh DS answer against the keys of `zone`, the zone the
    /// DS of `child` lives in, and caches the result.
    fn authenticate_ds(
        &self,
        zone: &str,
        child: &str,
        fresh: FreshDs,
    ) -> Result<DsLookup, DomainError> {
        let Some(zone_keys) = self.validated_keys.get(zone).cloned() else {
            warn!(zone = %zone, child = %child, "Zone keys not established; cannot authenticate DS answer");
            return Err(DomainError::InvalidDnsResponse(
                "Parent keys unavailable for DS validation".into(),
            ));
        };

        let child_name = to_fqdn(child).ok_or_else(|| {
            DomainError::InvalidDnsResponse(format!("unparseable DS owner {child}"))
        })?;

        if rrset_of(&fresh.answers, HRecordType::DS).next().is_none() {
            let lookup = DsLookup::Absent(self.prove_ds_absence(
                zone,
                child,
                &child_name,
                &fresh,
                zone_keys,
            )?);
            if let Some(ttl) = fresh.negative_ttl.filter(|ttl| *ttl > 0) {
                self.dnssec_cache
                    .cache_ds(child, lookup.clone(), ttl.min(MAX_NEGATIVE_DS_TTL));
            }
            return Ok(lookup);
        }

        // RFC 4035 §5.2: the DS RRset lives in — and is signed by — the parent
        // zone. It MUST verify with a key already established in the chain before
        // it is used to authenticate the child's keys; otherwise an on-path
        // attacker could inject a DS matching a key of their own.
        if !any_rrsig_verifies(
            &fresh.answers,
            HRecordType::DS,
            &zone_keys[..],
            &child_name,
            now_secs(),
        ) {
            warn!(zone = %zone, child = %child, "DS RRset not signed by a key of the zone");
            return Err(DomainError::InvalidDnsResponse(
                "DS RRSIG verification failed".into(),
            ));
        }

        let lookup = DsLookup::Present(Arc::from(fresh.records));
        self.dnssec_cache.cache_ds(child, lookup.clone(), fresh.ttl);
        Ok(lookup)
    }

    /// Classifies an empty DS answer from the parent's authenticated
    /// NSEC/NSEC3 (RFC 4035 §5.2). An empty answer costs nothing to forge, so
    /// without a signed proof it is a downgrade attempt, never an insecure
    /// delegation — even when the cause is an upstream that strips the
    /// authority section, since the two look identical on the wire.
    fn prove_ds_absence(
        &self,
        zone: &str,
        child: &str,
        child_name: &Name,
        fresh: &FreshDs,
        zone_keys: Arc<[DnskeyRecord]>,
    ) -> Result<DsDenial, DomainError> {
        let zone_name = to_fqdn(zone).ok_or_else(|| {
            DomainError::InvalidDnsResponse(format!("unparseable zone name {zone}"))
        })?;

        // Only the zone holding the DS may deny it.
        let (nsec3s, nsecs) =
            auth_check::collect_verified_denial(&fresh.authority, now_secs(), &|signer| {
                (signer == &zone_name).then(|| Arc::clone(&zone_keys))
            });

        if let Some(denial) =
            classify_ds_denial(child_name, fresh.rcode, &zone_name, &nsec3s, &nsecs)
        {
            debug!(zone = %zone, child = %child, ?denial, "DS absence proven");
            return Ok(denial);
        }

        if nsec3s.is_empty() && nsecs.is_empty() {
            self.dnssec_cache.record_ds_denial_unproven();
            warn!(
                zone = %zone,
                child = %child,
                "Empty DS answer without an authenticated NSEC/NSEC3 denial \
                 (forged, or the upstream strips DNSSEC proofs)"
            );
        } else {
            warn!(
                zone = %zone,
                child = %child,
                "Signed denial does not prove the DS RRset absent"
            );
        }
        Err(DomainError::InvalidDnsResponse(format!(
            "no authenticated proof that {child} has no DS"
        )))
    }

    async fn fetch_ds(
        pool: &PoolManager,
        domain: &str,
        timeout_ms: u64,
    ) -> Result<FreshDs, DomainError> {
        debug!(domain = %domain, "DS cache miss, querying DNS");

        let domain_arc: Arc<str> = Arc::from(domain);
        let upstream_result = pool
            .query(&domain_arc, &RecordType::DS, timeout_ms, true)
            .await
            .inspect_err(|e| warn!(domain = %domain, error = %e, "DS query failed"))?;

        let mut records = Vec::new();
        for record in &upstream_result.response.message.answers {
            let RData::DNSSEC(DNSSECRData::DS(ds)) = &record.data else {
                continue;
            };
            let digest_type = u8::from(ds.digest_type());
            // RFC 8624: the SHA-1 DS digest (type 1) MUST NOT be used for
            // validation. The record stays in `answers`, which the RRSIG covers.
            if digest_type == 1 {
                debug!(domain = %domain, "Ignoring SHA-1 DS digest (RFC 8624)");
                continue;
            }
            records.push(DsRecord {
                key_tag: ds.key_tag(),
                algorithm: u8::from(ds.algorithm()),
                digest_type,
                digest: ds.digest().to_vec(),
            });
        }

        debug!(domain = %domain, count = records.len(), "DS query successful");

        // Caching waits for `authenticate_ds`: caching unauthenticated data here
        // would let an injected DS set poison later lookups.
        let response = upstream_result.response;
        Ok(FreshDs {
            records,
            ttl: response.min_ttl.unwrap_or(3600),
            negative_ttl: response.negative_soa_ttl,
            rcode: response.rcode,
            answers: response.message.answers,
            authority: response.message.authorities,
        })
    }

    async fn fetch_dnskey(
        cache: &DnssecCache,
        pool: &PoolManager,
        domain: &str,
        timeout_ms: u64,
    ) -> Result<DnskeyQueryResult, DomainError> {
        if let Some(keys) = cache.get_dnskey(domain) {
            debug!(
                domain = %domain,
                count = keys.len(),
                "DNSKEY cache hit"
            );
            return Ok(DnskeyQueryResult {
                keys,
                answers: Vec::new(),
                from_cache: true,
                ttl: 0,
            });
        }

        debug!(domain = %domain, "DNSKEY cache miss, querying DNS");

        let domain_arc: Arc<str> = Arc::from(domain);
        let upstream_result = pool
            .query(&domain_arc, &RecordType::DNSKEY, timeout_ms, true)
            .await
            .inspect_err(|e| warn!(domain = %domain, error = %e, "DNSKEY query failed"))?;

        let keys: Vec<DnskeyRecord> = rrset_of(
            &upstream_result.response.message.answers,
            HRecordType::DNSKEY,
        )
        .filter_map(|record| match &record.data {
            RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => {
                let pk = dnskey.public_key();
                Some(DnskeyRecord {
                    flags: dnskey.flags(),
                    protocol: 3,
                    algorithm: u8::from(<dyn PublicKey>::algorithm(pk)),
                    public_key: <dyn PublicKey>::public_bytes(pk).to_vec(),
                })
            }
            _ => None,
        })
        .collect();

        debug!(domain = %domain, keys = keys.len(), "DNSKEY query successful");

        // Caching waits for the self-signature check in `step`: caching an
        // unvalidated key set here would let injected keys poison later lookups.
        let response = upstream_result.response;
        Ok(DnskeyQueryResult {
            keys: Arc::from(keys),
            ttl: response.min_ttl.unwrap_or(3600),
            answers: response.message.answers,
            from_cache: false,
        })
    }

    /// Establishes the validated root DNSKEY RRset (KSK + ZSK) from the
    /// configured KSK trust anchors, storing it as the keys of the `.` zone.
    ///
    /// A trust anchor only pins a root KSK, but the DS RRset of every TLD is
    /// signed by the root *ZSK*. So we fetch the live root DNSKEY RRset, confirm
    /// it contains at least one anchored KSK, verify the RRset's self-signature
    /// against one of them (RFC 4035 §5.2), and only then trust the whole set —
    /// which now includes the ZSK needed to authenticate TLD DS records.
    ///
    /// Every anchored key is tried, not just the first: across a root KSK
    /// rollover the outgoing and incoming keys are published side by side for
    /// months, and only one of them signs the RRset at any given moment.
    async fn bootstrap_root_keys(&mut self) -> Result<(), DomainError> {
        // Already established by an earlier walk of this validation.
        if self.validated_keys.contains_key(".") {
            return Ok(());
        }
        let dnskey_result =
            Self::fetch_dnskey(&self.dnssec_cache, &self.pool_manager, ".", self.timeout_ms)
                .await?;

        if dnskey_result.keys.is_empty() {
            return Err(DomainError::InvalidDnsResponse(
                "No root DNSKEY records".into(),
            ));
        }

        // A cache hit was already validated against the anchors on first fetch.
        if dnskey_result.from_cache {
            self.validated_keys
                .insert(".".to_string(), dnskey_result.keys);
            return Ok(());
        }

        // At least one configured anchor must be present in the live root RRset.
        let anchor_keys = self
            .trust_store
            .anchor_keys_present(".", &dnskey_result.keys);

        if anchor_keys.is_empty() {
            return Err(DomainError::InvalidDnsResponse(format!(
                "Root DNSKEY RRset contains none of the {} configured trust anchors",
                self.trust_store.len()
            )));
        }

        if !any_rrsig_verifies(
            &dnskey_result.answers,
            HRecordType::DNSKEY,
            &anchor_keys,
            &Name::root(),
            now_secs(),
        ) {
            return Err(DomainError::InvalidDnsResponse(format!(
                "Root DNSKEY RRset not self-signed by any of {} anchored key(s)",
                anchor_keys.len()
            )));
        }

        debug!(
            anchored_keys = anchor_keys.len(),
            "Root DNSKEY RRset bootstrapped from trust anchors"
        );
        self.warn_on_unanchored_root_ksks(&dnskey_result.keys);

        self.dnssec_cache
            .cache_dnskey(".", Arc::clone(&dnskey_result.keys), dnskey_result.ttl);
        self.validated_keys
            .insert(".".to_string(), dnskey_result.keys);
        Ok(())
    }

    /// Early warning for the next root KSK rollover. The root publishes an
    /// incoming KSK months before it starts signing with it, so a KSK that no
    /// configured anchor pins is harmless today and fatal the day the root
    /// switches over. Say so while there is still time to act.
    ///
    /// Runs only on a cache miss, so at most once per root DNSKEY TTL (~2 days).
    fn warn_on_unanchored_root_ksks(&self, keys: &[DnskeyRecord]) {
        for key in self.trust_store.unanchored_ksks(".", keys) {
            warn!(
                key_tag = key.calculate_key_tag(),
                algorithm = key.algorithm,
                "Root zone publishes a KSK that no configured trust anchor covers; \
                 DNSSEC validation will break once the root signs with it — update the trust anchors"
            );
        }
    }

    pub fn get_zone_keys(&self, zone: &str) -> Option<&Arc<[DnskeyRecord]>> {
        self.validated_keys.get(zone)
    }
}

/// The names a walk visits on its way down to `fqdn`, shortest first, as
/// slices of it: `test.`, `example.test.`, `www.example.test.`.
fn descending_suffixes(fqdn: &str) -> impl Iterator<Item = &str> {
    let body = fqdn.strip_suffix('.').unwrap_or(fqdn);
    body.rmatch_indices('.')
        .map(|(dot, _)| &fqdn[dot + 1..])
        .chain((!body.is_empty()).then_some(fqdn))
}
