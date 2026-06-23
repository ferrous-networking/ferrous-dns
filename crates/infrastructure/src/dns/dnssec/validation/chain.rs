use crate::dns::dnssec::cache::DnssecCache;
use crate::dns::dnssec::crypto::SignatureVerifier;
use crate::dns::dnssec::trust_anchor::TrustAnchorStore;
use crate::dns::dnssec::types::{DnskeyRecord, DsRecord, RrsigRecord};
use crate::dns::forwarding::record_type_map::RecordTypeMapper;
use crate::dns::load_balancer::PoolManager;
use ferrous_dns_domain::{DnssecStatus, DomainError, RecordType};
use hickory_proto::dnssec::rdata::DNSSECRData;
use hickory_proto::dnssec::PublicKey;
use hickory_proto::rr::{RData, Record};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, warn};

/// Whether an error reflects an inability to reach/parse the upstream (so we
/// could not validate) rather than a genuine validation failure. Transient
/// errors fail open (Indeterminate); everything else is treated as Bogus.
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

/// Current UNIX time in seconds, clamped to `u32` (the RRSIG timestamp domain).
fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    Secure,

    Insecure,

    Bogus,

    Indeterminate,
}

impl ValidationResult {
    /// Canonical status string, sourced from the domain [`DnssecStatus`] enum so
    /// the validator's output cannot drift from the strings the rest of the
    /// system compares against and persists.
    pub fn as_str(&self) -> &'static str {
        DnssecStatus::from(*self).as_str()
    }
}

impl From<ValidationResult> for DnssecStatus {
    fn from(value: ValidationResult) -> Self {
        match value {
            ValidationResult::Secure => DnssecStatus::Secure,
            ValidationResult::Insecure => DnssecStatus::Insecure,
            ValidationResult::Bogus => DnssecStatus::Bogus,
            ValidationResult::Indeterminate => DnssecStatus::Indeterminate,
        }
    }
}

struct DnskeyQueryResult {
    keys: Arc<[DnskeyRecord]>,
    rrsigs: Vec<RrsigRecord>,
    raw_records: Vec<Record>,
    /// True when the keys came from the DNSKEY cache (already validated on the
    /// original fetch) rather than a fresh upstream response that still needs
    /// its self-signature checked.
    from_cache: bool,
    /// TTL to cache the validated key set under, once validation succeeds.
    ttl: u32,
}

struct DsQueryResult {
    /// DS records usable for validation (SHA-1 digests dropped per RFC 8624).
    records: Arc<[DsRecord]>,
    /// RRSIG(s) covering the DS RRset, signed by the parent zone.
    rrsigs: Vec<RrsigRecord>,
    /// The *complete* DS RRset as received (including any SHA-1 entries), needed
    /// to reconstruct the signed data when verifying `rrsigs`.
    raw_records: Vec<Record>,
    /// True when the records came from the DS cache (already parent-authenticated
    /// on the original fetch) rather than a fresh upstream response.
    from_cache: bool,
    /// TTL to cache the authenticated DS set under, once validation succeeds.
    ttl: u32,
}

pub struct ChainVerifier {
    pool_manager: Arc<PoolManager>,
    trust_store: TrustAnchorStore,
    crypto_verifier: SignatureVerifier,

    validated_keys: HashMap<String, Arc<[DnskeyRecord]>>,

    dnssec_cache: Arc<DnssecCache>,
}

impl ChainVerifier {
    pub fn new(
        pool_manager: Arc<PoolManager>,
        trust_store: TrustAnchorStore,
        dnssec_cache: Arc<DnssecCache>,
    ) -> Self {
        Self {
            pool_manager,
            trust_store,
            crypto_verifier: SignatureVerifier,
            validated_keys: HashMap::new(),
            dnssec_cache,
        }
    }

    pub async fn verify_chain(
        &mut self,
        domain: &str,
        record_type: RecordType,
    ) -> Result<ValidationResult, DomainError> {
        debug!(
            domain = %domain,
            record_type = ?record_type,
            "Starting DNSSEC chain verification"
        );

        if self.trust_store.get_anchor(".").is_none() {
            warn!("No root trust anchor configured");
            return Ok(ValidationResult::Indeterminate);
        }

        let labels = Self::split_domain(domain);
        debug!(labels = ?labels, "Domain labels");

        // Turn the configured KSK trust anchor into the full validated root
        // DNSKEY RRset (KSK + ZSK). The bare anchor KSK is not enough: the DS
        // RRset of each TLD is signed by the root *ZSK*, so without the ZSK the
        // first delegation's DS could not be authenticated. Done on every walk —
        // it is cache-backed (a hit re-uses the already-validated set), so it
        // stays cheap while still honouring the DNSKEY TTL and root key rollover.
        match self.bootstrap_root_keys().await {
            Ok(()) => {}
            Err(e) => {
                warn!(error = %e, "Root key bootstrap failed");
                if is_transient_error(&e) {
                    return Ok(ValidationResult::Indeterminate);
                }
                return Ok(ValidationResult::Bogus);
            }
        }

        let mut current_domain = String::from(".");

        for label in &labels {
            let child_domain = if current_domain == "." {
                format!("{}.", label)
            } else {
                format!("{}.{}", label, current_domain)
            };

            debug!(
                parent = %current_domain,
                child = %child_domain,
                "Validating delegation"
            );

            match self
                .validate_delegation(&current_domain, &child_domain)
                .await
            {
                Ok(()) => {
                    debug!(domain = %child_domain, "Delegation validated");
                }
                Err(DomainError::InsecureDelegation) => {
                    debug!(
                        parent = %current_domain,
                        child = %child_domain,
                        "Insecure delegation: no DS records, chain is unsigned"
                    );
                    return Ok(ValidationResult::Insecure);
                }
                Err(e) => {
                    warn!(
                        parent = %current_domain,
                        child = %child_domain,
                        error = %e,
                        "Delegation validation failed"
                    );
                    // A transport/network failure means we *couldn't* validate,
                    // not that the data is forged. Fail open (Indeterminate) so a
                    // transient upstream issue doesn't SERVFAIL signed domains in
                    // Strict mode; only genuine crypto/structural failures are Bogus.
                    if is_transient_error(&e) {
                        return Ok(ValidationResult::Indeterminate);
                    }
                    return Ok(ValidationResult::Bogus);
                }
            }

            current_domain = child_domain;
        }

        debug!(
            domain = %domain,
            "Chain of trust validated successfully"
        );

        Ok(ValidationResult::Secure)
    }

    async fn validate_delegation(
        &mut self,
        parent_domain: &str,
        child_domain: &str,
    ) -> Result<(), DomainError> {
        let (ds_result, dnskey_result) = tokio::join!(
            Self::fetch_ds(&self.dnssec_cache, &self.pool_manager, child_domain),
            Self::fetch_dnskey(&self.dnssec_cache, &self.pool_manager, child_domain),
        );

        let ds_result = ds_result?;

        if ds_result.records.is_empty() {
            debug!(domain = %child_domain, "No DS records found (insecure delegation)");
            return Err(DomainError::InsecureDelegation);
        }

        // RFC 4035 §5.2: the DS RRset lives in — and is signed by — the *parent*
        // zone. Before any DS is used to authenticate the child's keys, the DS
        // RRset itself MUST be verified with a parent key already established in
        // the chain of trust. Without this the validator merely trusts whatever
        // DS the upstream returned: an on-path attacker (plaintext Do53, or any
        // untrusted upstream) could inject a DS matching an attacker-generated
        // KSK, serve a self-signed DNSKEY RRset and ZSK-signed answers, and have
        // the whole forged branch accepted as Secure / AD=1.
        //
        // A cache hit is exempt: the DS cache is populated only *after* this
        // check passes (below), so cached DS records are already
        // parent-authenticated — and the cache does not retain the RRSIGs.
        if !ds_result.from_cache {
            let Some(parent_keys) = self.validated_keys.get(parent_domain).cloned() else {
                warn!(
                    parent = %parent_domain,
                    child = %child_domain,
                    "Parent zone keys not established; cannot authenticate DS RRset"
                );
                return Err(DomainError::InvalidDnsResponse(
                    "Parent keys unavailable for DS validation".into(),
                ));
            };

            if ds_result.rrsigs.is_empty() || ds_result.raw_records.is_empty() {
                warn!(
                    parent = %parent_domain,
                    child = %child_domain,
                    "DS RRset carried no RRSIG; cannot anchor it to the parent zone"
                );
                return Err(DomainError::InvalidDnsResponse(
                    "DS RRset missing RRSIG".into(),
                ));
            }

            let now = now_secs();
            let mut ds_authentic = false;
            'ds: for rrsig in &ds_result.rrsigs {
                for key in parent_keys.iter() {
                    match self.crypto_verifier.verify_rrsig(
                        rrsig,
                        key,
                        child_domain,
                        &ds_result.raw_records,
                        now,
                    ) {
                        Ok(true) => {
                            debug!(
                                parent = %parent_domain,
                                child = %child_domain,
                                key_tag = key.calculate_key_tag(),
                                "DS RRSIG verified against parent key"
                            );
                            ds_authentic = true;
                            break 'ds;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!(error = %e, "DS RRSIG verification error");
                        }
                    }
                }
            }

            if !ds_authentic {
                warn!(
                    parent = %parent_domain,
                    child = %child_domain,
                    "DS RRSIG did not verify against any parent key"
                );
                return Err(DomainError::InvalidDnsResponse(
                    "DS RRSIG verification failed".into(),
                ));
            }

            // Parent-authenticated ⇒ safe to cache the usable DS set now.
            self.dnssec_cache
                .cache_ds(child_domain, ds_result.records.to_vec(), ds_result.ttl);
        }

        // RFC 6840 §5.2: the DS RRset's algorithm field names the algorithm the
        // child zone signs with. If this build implements none of the algorithms
        // in the (now parent-authenticated) DS RRset, there is no usable
        // authentication path into the child — it MUST be treated as Insecure
        // (served, AD=0), exactly as a missing DS, NOT Bogus. Without this the walk
        // continues and the child's DNSKEY self-signature — necessarily in that
        // same unsupported algorithm — fails to verify, so the zone is wrongly
        // flagged Bogus and SERVFAIL'd in Strict mode.
        if !ds_result
            .records
            .iter()
            .any(|ds| SignatureVerifier::is_supported_algorithm(ds.algorithm))
        {
            debug!(
                domain = %child_domain,
                "DS RRset references only unsupported algorithms; treating child as insecure"
            );
            return Err(DomainError::InsecureDelegation);
        }

        let dnskey_result = dnskey_result?;

        if dnskey_result.keys.is_empty() {
            warn!(domain = %child_domain, "No DNSKEY records found");
            return Err(DomainError::InvalidDnsResponse(
                "No DNSKEY records found".into(),
            ));
        }

        let mut validated_keys = Vec::new();

        for ds in ds_result.records.iter() {
            for dnskey in dnskey_result.keys.iter() {
                match self.crypto_verifier.verify_ds(ds, dnskey, child_domain) {
                    Ok(true) => {
                        debug!(
                            domain = %child_domain,
                            key_tag = dnskey.calculate_key_tag(),
                            "DS validation successful"
                        );
                        validated_keys.push(dnskey.clone());
                        break;
                    }
                    Ok(false) => {
                        debug!(
                            domain = %child_domain,
                            ds_tag = ds.key_tag,
                            key_tag = dnskey.calculate_key_tag(),
                            "DS does not match DNSKEY"
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "DS verification error");
                    }
                }
            }
        }

        if validated_keys.is_empty() {
            warn!(
                domain = %child_domain,
                "No DNSKEY matched any DS record"
            );
            return Err(DomainError::InvalidDnsResponse(
                "No matching DNSKEY for DS".into(),
            ));
        }

        // RFC 4035 §5.2: before *any* key in the DNSKEY RRset is trusted, the RRset
        // must be validated with a key that a DS RR refers to. A fresh (cache-miss)
        // response therefore MUST carry a self-signature that verifies against a
        // DS-matched key; otherwise the zone is Bogus. Trusting every returned key
        // without this check would let an on-path attacker inject a rogue ZSK (with
        // the DNSKEY RRSIGs stripped) and have answers it signs accepted as Secure.
        //
        // A cache hit is exempt: the DNSKEY cache is only populated *below*, after a
        // successful self-signature validation, so cached keys are already
        // authenticated — and the cache does not retain the RRSIGs needed to re-check.
        if !dnskey_result.from_cache {
            if dnskey_result.rrsigs.is_empty() || dnskey_result.raw_records.is_empty() {
                warn!(
                    domain = %child_domain,
                    "DNSKEY RRset carried no self-signature; cannot establish trust"
                );
                return Err(DomainError::InvalidDnsResponse(
                    "DNSKEY RRset missing self-signature".into(),
                ));
            }

            let now = now_secs();

            let mut rrsig_ok = false;
            'outer: for rrsig in &dnskey_result.rrsigs {
                for key in &validated_keys {
                    match self.crypto_verifier.verify_rrsig(
                        rrsig,
                        key,
                        child_domain,
                        &dnskey_result.raw_records,
                        now,
                    ) {
                        Ok(true) => {
                            debug!(
                                domain = %child_domain,
                                key_tag = key.calculate_key_tag(),
                                "DNSKEY RRSIG verified"
                            );
                            rrsig_ok = true;
                            break 'outer;
                        }
                        Ok(false) => {}
                        Err(e) => {
                            warn!(error = %e, "RRSIG verification error");
                        }
                    }
                }
            }

            if !rrsig_ok {
                warn!(
                    domain = %child_domain,
                    "DNSKEY RRSIG verification failed for all keys"
                );
                return Err(DomainError::InvalidDnsResponse(
                    "DNSKEY RRSIG verification failed".into(),
                ));
            }

            // Self-signature verified by a DS-matched key ⇒ every key in the RRset
            // (KSK + ZSKs) is now authenticated. Persist only this validated set so
            // later lookups skip the round trip without re-checking.
            self.dnssec_cache.cache_dnskey(
                child_domain,
                dnskey_result.keys.to_vec(),
                dnskey_result.ttl,
            );
        }

        self.validated_keys
            .insert(child_domain.to_string(), dnskey_result.keys);

        Ok(())
    }

    async fn fetch_ds(
        cache: &DnssecCache,
        pool: &PoolManager,
        domain: &str,
    ) -> Result<DsQueryResult, DomainError> {
        if let Some(records) = cache.get_ds(domain) {
            debug!(
                domain = %domain,
                count = records.len(),
                "DS cache hit"
            );
            return Ok(DsQueryResult {
                records,
                rrsigs: vec![],
                raw_records: vec![],
                from_cache: true,
                ttl: 0,
            });
        }

        debug!(domain = %domain, "DS cache miss, querying DNS");

        let domain_arc: Arc<str> = Arc::from(domain);
        let result = pool.query(&domain_arc, &RecordType::DS, 5000, true).await;

        match result {
            Ok(upstream_result) => {
                let mut records = Vec::new();
                let mut rrsigs = Vec::new();
                let mut raw_records = Vec::new();

                for record in &upstream_result.response.raw_answers {
                    match record.data() {
                        RData::DNSSEC(DNSSECRData::DS(ds)) => {
                            // The DS RRSIG covers the *complete* DS RRset as
                            // published, so every DS record (SHA-1 included) is
                            // needed to reconstruct the signed data, even though
                            // SHA-1 digests are not used for digest matching.
                            raw_records.push(record.clone());

                            let digest_type = u8::from(ds.digest_type());
                            // RFC 8624: the SHA-1 DS digest (type 1) MUST NOT be
                            // used for validation. Dropping it here means a
                            // delegation that publishes only SHA-1 DS records is
                            // treated as having no usable DS (Insecure, served,
                            // AD=0), while a zone that also publishes a
                            // SHA-256/384 DS validates against the stronger digest.
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
                        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                            let input = rrsig.input();
                            if input.type_covered != hickory_proto::rr::RecordType::DS {
                                continue;
                            }
                            let Some(type_covered) =
                                RecordTypeMapper::from_hickory(input.type_covered)
                            else {
                                continue;
                            };
                            rrsigs.push(RrsigRecord {
                                type_covered,
                                algorithm: u8::from(input.algorithm),
                                labels: input.num_labels,
                                original_ttl: input.original_ttl,
                                signature_expiration: input.sig_expiration.get(),
                                signature_inception: input.sig_inception.get(),
                                key_tag: input.key_tag,
                                signer_name: input.signer_name.to_string(),
                                signature: rrsig.sig().to_vec(),
                            });
                        }
                        _ => {}
                    }
                }

                debug!(
                    domain = %domain,
                    count = records.len(),
                    rrsigs = rrsigs.len(),
                    "DS query successful"
                );

                // Caching is deferred to validate_delegation, which caches the DS
                // set only *after* its RRSIG has been verified against a parent
                // key. Caching here would let an unauthenticated (possibly
                // attacker-injected) DS set poison later lookups.
                let ttl = upstream_result.response.min_ttl.unwrap_or(3600);

                Ok(DsQueryResult {
                    records: Arc::from(records),
                    rrsigs,
                    raw_records,
                    from_cache: false,
                    ttl,
                })
            }
            Err(e) => {
                warn!(domain = %domain, error = %e, "DS query failed");
                Err(e)
            }
        }
    }

    async fn fetch_dnskey(
        cache: &DnssecCache,
        pool: &PoolManager,
        domain: &str,
    ) -> Result<DnskeyQueryResult, DomainError> {
        if let Some(keys) = cache.get_dnskey(domain) {
            debug!(
                domain = %domain,
                count = keys.len(),
                "DNSKEY cache hit"
            );
            return Ok(DnskeyQueryResult {
                keys,
                rrsigs: vec![],
                raw_records: vec![],
                from_cache: true,
                ttl: 0,
            });
        }

        debug!(domain = %domain, "DNSKEY cache miss, querying DNS");

        let domain_arc: Arc<str> = Arc::from(domain);
        let result = pool
            .query(&domain_arc, &RecordType::DNSKEY, 5000, true)
            .await;

        match result {
            Ok(upstream_result) => {
                let mut keys = Vec::new();
                let mut rrsigs = Vec::new();
                let mut raw_records = Vec::new();

                for record in &upstream_result.response.raw_answers {
                    match record.data() {
                        RData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) => {
                            let pk = dnskey.public_key();
                            keys.push(DnskeyRecord {
                                flags: dnskey.flags(),
                                protocol: 3,
                                algorithm: u8::from(<dyn PublicKey>::algorithm(pk)),
                                public_key: <dyn PublicKey>::public_bytes(pk).to_vec(),
                            });
                            raw_records.push(record.clone());
                        }
                        RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                            let input = rrsig.input();
                            if input.type_covered != hickory_proto::rr::RecordType::DNSKEY {
                                continue;
                            }
                            let Some(type_covered) =
                                RecordTypeMapper::from_hickory(input.type_covered)
                            else {
                                continue;
                            };
                            rrsigs.push(RrsigRecord {
                                type_covered,
                                algorithm: u8::from(input.algorithm),
                                labels: input.num_labels,
                                original_ttl: input.original_ttl,
                                signature_expiration: input.sig_expiration.get(),
                                signature_inception: input.sig_inception.get(),
                                key_tag: input.key_tag,
                                signer_name: input.signer_name.to_string(),
                                signature: rrsig.sig().to_vec(),
                            });
                        }
                        _ => {}
                    }
                }

                debug!(
                    domain = %domain,
                    keys = keys.len(),
                    rrsigs = rrsigs.len(),
                    "DNSKEY query successful"
                );

                // Caching is deferred to validate_delegation, which only caches
                // the key set *after* its DNSKEY self-signature has been verified
                // against a DS-matched key. Caching here would let an unvalidated
                // (potentially attacker-injected) key set poison later lookups.
                let ttl = upstream_result.response.min_ttl.unwrap_or(3600);

                let keys_arc: Arc<[DnskeyRecord]> = Arc::from(keys);
                Ok(DnskeyQueryResult {
                    keys: keys_arc,
                    rrsigs,
                    raw_records,
                    from_cache: false,
                    ttl,
                })
            }
            Err(e) => {
                warn!(domain = %domain, error = %e, "DNSKEY query failed");
                Err(e)
            }
        }
    }

    /// Establishes the validated root DNSKEY RRset (KSK + ZSK) from the
    /// configured KSK trust anchor, storing it as the keys of the `.` zone.
    ///
    /// The trust anchor only pins the root KSK, but the DS RRset of every TLD is
    /// signed by the root *ZSK*. So we fetch the live root DNSKEY RRset, confirm
    /// it contains the anchor KSK, verify the RRset's self-signature against that
    /// KSK (RFC 4035 §5.2), and only then trust the whole set — which now
    /// includes the ZSK needed to authenticate TLD DS records.
    async fn bootstrap_root_keys(&mut self) -> Result<(), DomainError> {
        let anchor = match self.trust_store.get_anchor(".") {
            Some(a) => a.clone(),
            None => {
                return Err(DomainError::InvalidDnsResponse(
                    "No root trust anchor configured".into(),
                ))
            }
        };

        let dnskey_result = Self::fetch_dnskey(&self.dnssec_cache, &self.pool_manager, ".").await?;

        if dnskey_result.keys.is_empty() {
            return Err(DomainError::InvalidDnsResponse(
                "No root DNSKEY records".into(),
            ));
        }

        // A cache hit was already validated against the anchor on first fetch.
        if dnskey_result.from_cache {
            self.validated_keys
                .insert(".".to_string(), dnskey_result.keys);
            return Ok(());
        }

        // The configured anchor KSK must be present in the live root RRset.
        let Some(anchor_key) = dnskey_result
            .keys
            .iter()
            .find(|k| anchor.matches(k))
            .cloned()
        else {
            return Err(DomainError::InvalidDnsResponse(
                "Root DNSKEY RRset does not contain the trust anchor".into(),
            ));
        };

        if dnskey_result.rrsigs.is_empty() || dnskey_result.raw_records.is_empty() {
            return Err(DomainError::InvalidDnsResponse(
                "Root DNSKEY RRset carried no self-signature".into(),
            ));
        }

        let now = now_secs();
        let mut rrsig_ok = false;
        for rrsig in &dnskey_result.rrsigs {
            match self.crypto_verifier.verify_rrsig(
                rrsig,
                &anchor_key,
                ".",
                &dnskey_result.raw_records,
                now,
            ) {
                Ok(true) => {
                    rrsig_ok = true;
                    break;
                }
                Ok(false) => {}
                Err(e) => {
                    warn!(error = %e, "Root DNSKEY RRSIG verification error");
                }
            }
        }

        if !rrsig_ok {
            return Err(DomainError::InvalidDnsResponse(
                "Root DNSKEY self-signature verification failed".into(),
            ));
        }

        self.dnssec_cache
            .cache_dnskey(".", dnskey_result.keys.to_vec(), dnskey_result.ttl);
        self.validated_keys
            .insert(".".to_string(), dnskey_result.keys);

        debug!("Root DNSKEY RRset bootstrapped from trust anchor");
        Ok(())
    }

    pub fn get_zone_keys(&self, zone: &str) -> Option<&Arc<[DnskeyRecord]>> {
        self.validated_keys.get(zone)
    }

    pub fn insert_zone_keys_for_test(&mut self, zone: &str, keys: Vec<DnskeyRecord>) {
        self.validated_keys
            .insert(zone.to_string(), Arc::from(keys));
    }

    pub fn split_domain(domain: &str) -> Vec<&str> {
        let domain = domain.trim_end_matches('.');

        if domain.is_empty() || domain == "." {
            return Vec::new();
        }

        domain.split('.').rev().collect()
    }
}
