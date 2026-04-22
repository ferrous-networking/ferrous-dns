use super::super::cache::key::CacheKey;
use super::super::cache::negative_cache::clamp_negative_ttl;
use super::super::cache::{
    CachedAddresses, CachedData, DnsCacheAccess, DnssecStatus, NegativeQueryTracker,
};
use super::super::prefetch::PrefetchPredictor;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, EMPTY_CNAME_CHAIN};
use std::cell::Cell;
use std::sync::LazyLock;

static EMPTY_ADDRESSES: LazyLock<Arc<Vec<IpAddr>>> = LazyLock::new(|| Arc::new(vec![]));
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;

struct InflightResult {
    addresses: Arc<Vec<IpAddr>>,
    cname_chain: Arc<[Arc<str>]>,
    dnssec_status: Option<&'static str>,
    min_ttl: Option<u32>,
    upstream_wire_data: Option<Bytes>,
}

type InflightSender = Arc<watch::Sender<Option<Arc<InflightResult>>>>;

struct InflightLeaderGuard {
    inflight: Arc<DashMap<CacheKey, InflightSender, FxBuildHasher>>,
    key: CacheKey,
    defused: Cell<bool>,
}

impl InflightLeaderGuard {
    fn defuse(&self) {
        self.defused.set(true);
    }
}

impl Drop for InflightLeaderGuard {
    fn drop(&mut self) {
        if !self.defused.get() {
            if let Some((_, tx)) = self.inflight.remove(&self.key) {
                let _ = tx.send(None);
            }
        }
    }
}

pub struct CachedResolver {
    inner: Arc<dyn DnsResolver>,
    cache: Arc<dyn DnsCacheAccess>,
    cache_ttl: u32,
    negative_ttl_tracker: Arc<NegativeQueryTracker>,
    prefetch_predictor: Option<Arc<PrefetchPredictor>>,
    inflight: Arc<DashMap<CacheKey, InflightSender, FxBuildHasher>>,
}

impl CachedResolver {
    pub fn new(
        inner: Arc<dyn DnsResolver>,
        cache: Arc<dyn DnsCacheAccess>,
        cache_ttl: u32,
        negative_ttl_tracker: Arc<NegativeQueryTracker>,
        inflight_shards: usize,
    ) -> Self {
        Self {
            inner,
            cache,
            cache_ttl,
            negative_ttl_tracker,
            prefetch_predictor: None,
            // In-flight entries are transient — use caller-configured shard count
            // (default = cache_inflight_shards from TOML, typically cpus*2 next_power_of_two).
            inflight: Arc::new(DashMap::with_capacity_and_hasher_and_shard_amount(
                0,
                FxBuildHasher,
                inflight_shards,
            )),
        }
    }

    pub fn with_prefetch(mut self, predictor: Arc<PrefetchPredictor>) -> Self {
        self.prefetch_predictor = Some(predictor);
        self
    }

    fn check_cache_str(&self, domain: &str, record_type: RecordType) -> Option<DnsResolution> {
        self.cache
            .get(domain, &record_type)
            .map(|(data, dnssec_status, remaining_ttl)| {
                let dnssec_str = dnssec_status.map(|s| s.as_str());
                match data {
                    CachedData::IpAddresses(entry) => DnsResolution {
                        addresses: Arc::clone(&entry.addresses),
                        cache_hit: true,
                        local_dns: false,
                        dnssec_status: dnssec_str,
                        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
                        upstream_server: None,
                        upstream_pool: None,
                        min_ttl: remaining_ttl,
                        negative_soa_ttl: None,
                        upstream_wire_data: None,
                    },
                    CachedData::CanonicalName(name) => DnsResolution {
                        addresses: Arc::clone(&EMPTY_ADDRESSES),
                        cache_hit: true,
                        local_dns: false,
                        dnssec_status: dnssec_str,
                        cname_chain: Arc::from([Arc::clone(&name)]),
                        upstream_server: None,
                        upstream_pool: None,
                        min_ttl: remaining_ttl,
                        negative_soa_ttl: None,
                        upstream_wire_data: None,
                    },
                    CachedData::WireData(bytes) => DnsResolution {
                        addresses: Arc::clone(&EMPTY_ADDRESSES),
                        cache_hit: true,
                        local_dns: false,
                        dnssec_status: dnssec_str,
                        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
                        upstream_server: None,
                        upstream_pool: None,
                        min_ttl: remaining_ttl,
                        negative_soa_ttl: None,
                        upstream_wire_data: Some(bytes),
                    },
                    CachedData::NegativeResponse => DnsResolution {
                        addresses: Arc::clone(&EMPTY_ADDRESSES),
                        cache_hit: true,
                        local_dns: false,
                        dnssec_status: dnssec_str,
                        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
                        upstream_server: None,
                        upstream_pool: None,
                        min_ttl: remaining_ttl,
                        negative_soa_ttl: None,
                        upstream_wire_data: None,
                    },
                }
            })
    }

    fn check_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        self.check_cache_str(query.domain.as_ref(), query.record_type)
    }

    fn insert_negative(&self, query: &DnsQuery) {
        let ttl = self.negative_ttl_tracker.record_and_get_ttl(&query.domain);
        self.cache.insert(
            query.domain.as_ref(),
            query.record_type,
            CachedData::NegativeResponse,
            ttl,
            Some(DnssecStatus::Insecure),
        );
    }

    fn store_in_cache(&self, query: &DnsQuery, resolution: &DnsResolution) {
        if resolution.addresses.is_empty() {
            if let Some(ref wire_data) = resolution.upstream_wire_data {
                let ttl = resolution.min_ttl.unwrap_or(self.cache_ttl).max(1);
                let dnssec_status = resolution
                    .dnssec_status
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(DnssecStatus::Insecure);
                self.cache.insert(
                    query.domain.as_ref(),
                    query.record_type,
                    CachedData::WireData(wire_data.clone()),
                    ttl,
                    Some(dnssec_status),
                );
            } else {
                let ttl = resolution
                    .negative_soa_ttl
                    .map(clamp_negative_ttl)
                    .unwrap_or_else(|| self.negative_ttl_tracker.record_and_get_ttl(&query.domain));
                self.cache.insert(
                    query.domain.as_ref(),
                    query.record_type,
                    CachedData::NegativeResponse,
                    ttl,
                    Some(DnssecStatus::Insecure),
                );
            }
        } else {
            let addresses = Arc::clone(&resolution.addresses);
            let dnssec_status = resolution
                .dnssec_status
                .and_then(|s| s.parse().ok())
                .unwrap_or(DnssecStatus::Insecure);

            let ttl = resolution.min_ttl.unwrap_or(self.cache_ttl);

            self.cache.insert(
                query.domain.as_ref(),
                query.record_type,
                CachedData::IpAddresses(CachedAddresses { addresses }),
                ttl,
                Some(dnssec_status),
            );

            // Phase 4: cache CNAME chain's final target as a separate entry.
            // When upstream resolves "www.foo.com A?" via chain
            // "www.foo.com CNAME cdn.foo.com, cdn.foo.com A 1.2.3.4",
            // we also persist "cdn.foo.com A -> [1.2.3.4]" so a direct query
            // for "cdn.foo.com A" hits the cache instead of escaping upstream.
            //
            // TTL: reuses the chain's min_ttl (already the minimum of all records
            // per RFC 1035 — response_parser.rs:68-69 computes min across the chain).
            // DNSSEC status: inherited from the qname entry — never elevated.
            //
            // TODO(bailiwick): RFC 2181 bailiwick check not implemented here —
            // the response parser currently accepts any CNAME target. If upstream
            // is untrusted and returns a cross-bailiwick CNAME, caching its target
            // could poison direct lookups. Mitigation today: DNSSEC validation
            // (when enabled) marks unverified responses accordingly, and we inherit
            // that status. Revisit if upstream trust becomes an operational concern.
            if let Some(final_target) = resolution.cname_chain.last() {
                let target_name: &str = final_target.as_ref();
                // Guard against accidental self-loop (qname == final target).
                // The lookups use case-insensitive cache keys (Phase 1), so compare
                // case-insensitively to avoid writing an identical entry twice.
                if !target_name.eq_ignore_ascii_case(query.domain.as_ref()) {
                    let target_addresses = Arc::clone(&resolution.addresses);
                    self.cache.insert(
                        target_name,
                        query.record_type,
                        CachedData::IpAddresses(CachedAddresses {
                            addresses: target_addresses,
                        }),
                        ttl,
                        Some(dnssec_status),
                    );
                }
            }

            if let Some(ref predictor) = self.prefetch_predictor {
                predictor.on_query(&query.domain);
            }
        }
    }

    fn register_or_join_inflight(
        &self,
        key: &CacheKey,
    ) -> (bool, watch::Receiver<Option<Arc<InflightResult>>>) {
        match self.inflight.entry(key.clone()) {
            dashmap::Entry::Occupied(e) => {
                let rx = e.get().subscribe();
                drop(e);
                (false, rx)
            }
            dashmap::Entry::Vacant(e) => {
                let (tx, rx) = watch::channel(None::<Arc<InflightResult>>);
                e.insert(Arc::new(tx));
                (true, rx)
            }
        }
    }

    async fn resolve_as_follower(
        &self,
        query: &DnsQuery,
        mut rx: watch::Receiver<Option<Arc<InflightResult>>>,
    ) -> Result<DnsResolution, DomainError> {
        if let Ok(()) = rx.changed().await {
            if let Some(result) = rx.borrow().clone() {
                return Ok(DnsResolution {
                    addresses: Arc::clone(&result.addresses),
                    cache_hit: true,
                    local_dns: false,
                    dnssec_status: result.dnssec_status,
                    cname_chain: Arc::clone(&result.cname_chain),
                    upstream_server: None,
                    upstream_pool: None,
                    min_ttl: result.min_ttl,
                    negative_soa_ttl: None,
                    upstream_wire_data: result.upstream_wire_data.clone(),
                });
            }
        }

        if let Some(result) = rx.borrow().clone() {
            return Ok(DnsResolution {
                addresses: Arc::clone(&result.addresses),
                cache_hit: true,
                local_dns: false,
                dnssec_status: result.dnssec_status,
                cname_chain: Arc::clone(&result.cname_chain),
                upstream_server: None,
                upstream_pool: None,
                min_ttl: result.min_ttl,
                negative_soa_ttl: None,
                upstream_wire_data: result.upstream_wire_data.clone(),
            });
        }

        if let Some(cached) = self.check_cache(query) {
            return if !cached.has_response_data() {
                Err(DomainError::NxDomain)
            } else {
                Ok(cached)
            };
        }

        self.resolve(query).await
    }

    async fn resolve_as_leader(
        &self,
        query: &DnsQuery,
        key: CacheKey,
    ) -> Result<DnsResolution, DomainError> {
        let guard = InflightLeaderGuard {
            inflight: Arc::clone(&self.inflight),
            key: key.clone(),
            defused: Cell::new(false),
        };

        // Phase 5: close the TOCTOU race between `register_or_join_inflight`
        // and this point. Between being elected leader and actually calling
        // the upstream, another concurrent leader (for a different record
        // type or stale follower path) may have populated the cache. If it
        // did, skip the upstream call entirely and wake any followers with
        // the cached result via the same watch channel.
        if let Some(cached) = self.check_cache(query) {
            // Wake any coalesced followers with the cache result via the same
            // watch channel used by the upstream-success branch, so the
            // follower path sees a consistent payload shape whether the
            // leader won the upstream race or short-circuited on the cache.
            self.publish_inflight(&key, &cached);
            guard.defuse();
            return if !cached.has_response_data() {
                Err(DomainError::NxDomain)
            } else {
                Ok(cached)
            };
        }

        let result = self.inner.resolve(query).await;

        match &result {
            Ok(resolution) => {
                self.store_in_cache(query, resolution);
                self.publish_inflight(&key, resolution);
                guard.defuse();
            }
            Err(ref err) => {
                // Phase 6: only cache responses that are genuine negative
                // answers (NXDOMAIN / LocalNxDomain). Transient upstream
                // failures (timeouts, refused/reset transports, no healthy
                // servers, malformed responses, rate limits, etc.) MUST NOT
                // populate the negative cache: doing so would serve fake
                // NXDOMAIN for 300–3600s while upstream recovers, turning
                // instability into apparent permanent outage for clients.
                if is_cacheable_negative(err) {
                    self.insert_negative(query);
                } else {
                    self.cache.record_transient_upstream_error();
                }
                self.fail_inflight(&key);
                guard.defuse();
            }
        }

        result
    }

    /// Removes the inflight entry for `key` and signals every follower that
    /// the leader failed (via `tx.send(None)`), prompting each follower to
    /// fall back to its own cache check and, if that misses, to re-run its
    /// own resolution. Mirrors the negative branch of [`publish_inflight`]
    /// so the failure path has a single, explicit call site.
    #[inline]
    fn fail_inflight(&self, key: &CacheKey) {
        if let Some((_, tx)) = self.inflight.remove(key) {
            let _ = tx.send(None);
        }
    }

    /// Removes the inflight entry for `key` atomically and publishes
    /// `resolution` to every subscribed follower via the stored watch sender.
    ///
    /// Shared by the upstream-success branch of [`resolve_as_leader`] and the
    /// cache-short-circuit path ([`wake_followers_with_cached`]), so followers
    /// always observe the same payload shape regardless of which branch won
    /// the race. A resolution without response data (negative answer / stale
    /// cache hit that lost its data) is published as `None` so followers
    /// translate it into `DomainError::NxDomain`.
    #[inline]
    fn publish_inflight(&self, key: &CacheKey, resolution: &DnsResolution) {
        let Some((_, tx)) = self.inflight.remove(key) else {
            return;
        };
        if !resolution.has_response_data() {
            let _ = tx.send(None);
            return;
        }
        let inflight = Arc::new(InflightResult {
            addresses: Arc::clone(&resolution.addresses),
            cname_chain: Arc::clone(&resolution.cname_chain),
            dnssec_status: resolution.dnssec_status,
            min_ttl: resolution.min_ttl,
            upstream_wire_data: resolution.upstream_wire_data.clone(),
        });
        let _ = tx.send(Some(inflight));
    }
}

/// Phase 6: classifies a resolver error as a cacheable negative answer or a
/// transient failure. Only `NxDomain` / `LocalNxDomain` represent the upstream
/// (or local server) authoritatively stating "this name does not exist" and
/// are safe to persist in the negative cache. Every other variant may flip
/// back to a successful resolution once the underlying condition clears
/// (network hiccup, server restart, rate-limiter window advance, etc.) —
/// caching them would serve fake NXDOMAIN to clients for the entire negative
/// TTL window.
#[inline]
fn is_cacheable_negative(err: &DomainError) -> bool {
    matches!(err, DomainError::NxDomain | DomainError::LocalNxDomain)
}

#[async_trait]
impl DnsResolver for CachedResolver {
    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        self.check_cache(query)
    }

    fn try_cache_str(&self, domain: &str, record_type: RecordType) -> Option<DnsResolution> {
        self.check_cache_str(domain, record_type)
    }

    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        if let Some(cached) = self.check_cache(query) {
            return if !cached.has_response_data() {
                Err(DomainError::NxDomain)
            } else {
                Ok(cached)
            };
        }

        let key = CacheKey::new(query.domain.as_ref(), query.record_type);
        let (is_leader, rx) = self.register_or_join_inflight(&key);

        if !is_leader {
            return self.resolve_as_follower(query, rx).await;
        }

        // Phase 5: the second cache-check that used to live here (and its
        // non-atomic `self.inflight.remove`) moved into `resolve_as_leader`,
        // where it runs *after* the guard is already in place. That closes
        // the TOCTOU race: a follower arriving between the leader election
        // above and the cache check could previously be orphaned by the
        // leader taking the shortcut and unregistering the inflight entry.
        self.resolve_as_leader(query, key).await
    }
}
