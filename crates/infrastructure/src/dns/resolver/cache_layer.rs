use super::super::cache::key::{BorrowedKey, CacheKey};
use super::super::cache::negative_cache::{negative_ttl, MIN_NEGATIVE_TTL};
use super::super::cache::{
    CachedAddresses, CachedData, CachedDnssecStatus, DnsCacheAccess, LocalRecordStatus,
};
use super::super::load_balancer::{Route, UpstreamRouter};
use super::super::wire_response;
use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, EMPTY_CNAME_CHAIN};
use ferrous_dns_domain::{DnsQuery, DnssecStatus, DomainError, RecordType};
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::sync::watch;

static EMPTY_ADDRESSES: LazyLock<Arc<Vec<IpAddr>>> = LazyLock::new(|| Arc::new(vec![]));

struct InflightResult {
    addresses: Arc<Vec<IpAddr>>,
    local_dns: bool,
    upstream_nxdomain: bool,
    cname_chain: Arc<[Arc<str>]>,
    dnssec_status: Option<DnssecStatus>,
    min_ttl: Option<u32>,
    upstream_wire_data: Option<Bytes>,
}

impl InflightResult {
    fn to_resolution(&self) -> DnsResolution {
        DnsResolution {
            addresses: Arc::clone(&self.addresses),
            cache_hit: true,
            local_dns: self.local_dns,
            local_nxdomain: false,
            upstream_nxdomain: self.upstream_nxdomain,
            dnssec_status: self.dnssec_status,
            cname_chain: Arc::clone(&self.cname_chain),
            upstream_server: None,
            upstream_pool: None,
            min_ttl: self.min_ttl,
            negative_soa_ttl: None,
            upstream_wire_data: self.upstream_wire_data.clone(),
        }
    }
}

type InflightSender = Arc<watch::Sender<Option<Arc<InflightResult>>>>;
type InflightMap = DashMap<CacheKey, InflightSender, FxBuildHasher>;

/// Releases the leader's in-flight slot on every exit it did not publish from,
/// so followers fall back to their own resolution instead of waiting forever.
struct InflightLeaderGuard<'a> {
    inflight: &'a InflightMap,
    key: CacheKey,
    defused: bool,
}

impl InflightLeaderGuard<'_> {
    /// Called once the slot has been published: by then a new leader may own
    /// the key, and removing it again would strand that leader's followers.
    fn defuse(&mut self) {
        self.defused = true;
    }
}

impl Drop for InflightLeaderGuard<'_> {
    fn drop(&mut self) {
        if !self.defused {
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
    inflight: InflightMap,
    /// Picks the cache view a client group's query reads and fills. Without
    /// one, every query uses the view all clients share.
    router: Option<Arc<dyn UpstreamRouter>>,
    /// The router's [`UpstreamRouter::group_routes_flag`], read inline so a
    /// cache hit skips the router while no route is scoped to a group.
    group_routes: Arc<AtomicBool>,
}

impl CachedResolver {
    pub fn new(
        inner: Arc<dyn DnsResolver>,
        cache: Arc<dyn DnsCacheAccess>,
        cache_ttl: u32,
        inflight_shards: usize,
    ) -> Self {
        Self {
            inner,
            cache,
            cache_ttl,
            inflight: DashMap::with_capacity_and_hasher_and_shard_amount(
                0,
                FxBuildHasher,
                inflight_shards,
            ),
            router: None,
            group_routes: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Keeps the answers a client group's own conditional pool gives apart
    /// from every other client's.
    pub fn with_router(mut self, router: Arc<dyn UpstreamRouter>) -> Self {
        self.group_routes = router.group_routes_flag();
        self.router = Some(router);
        self
    }

    /// The cache view `domain` is read from for `group`.
    #[inline]
    fn view(&self, domain: &str, group: Option<i64>) -> u32 {
        match &self.router {
            Some(router) if group.is_some() && self.group_routes.load(Ordering::Acquire) => {
                router.view(domain, group)
            }
            _ => 0,
        }
    }

    fn route(&self, query: &DnsQuery) -> Option<Route> {
        self.router
            .as_ref()
            .and_then(|router| router.route(&query.domain, query.group_id))
    }

    fn check_cache_str(
        &self,
        domain: &str,
        record_type: RecordType,
        view: u32,
    ) -> Option<DnsResolution> {
        let local_status = self.cache.local_record_status(domain, &record_type);
        let (data, dnssec_status, min_ttl, local_answer) = match local_status {
            // A configured address owns the name, not only its record type.
            // Answer before ordinary cached data so stale upstream data cannot win.
            LocalRecordStatus::MissingType => (CachedData::NegativeResponse, None, None, false),
            // A local record answers every client, so it lives in the shared view.
            LocalRecordStatus::Present => self.cache.get(domain, &record_type, 0)?,
            LocalRecordStatus::NotLocal => self.cache.get(domain, &record_type, view)?,
        };

        // A local server's NXDOMAIN must not read as `local_dns`, which on an
        // empty answer means NODATA.
        let (addresses, cname_chain, upstream_wire_data, local_nxdomain) = match data {
            CachedData::IpAddresses(entry) => {
                (entry.addresses, Arc::clone(&EMPTY_CNAME_CHAIN), None, false)
            }
            CachedData::CanonicalName(name) => {
                (Arc::clone(&EMPTY_ADDRESSES), Arc::from([name]), None, false)
            }
            CachedData::WireData(bytes) => (
                Arc::clone(&EMPTY_ADDRESSES),
                Arc::clone(&EMPTY_CNAME_CHAIN),
                Some(bytes),
                false,
            ),
            CachedData::NegativeResponse => (
                Arc::clone(&EMPTY_ADDRESSES),
                Arc::clone(&EMPTY_CNAME_CHAIN),
                None,
                local_answer,
            ),
        };

        Some(DnsResolution {
            addresses,
            cache_hit: true,
            local_dns: (local_answer && !local_nxdomain)
                || local_status != LocalRecordStatus::NotLocal,
            local_nxdomain,
            upstream_nxdomain: upstream_wire_data
                .as_deref()
                .is_some_and(wire_response::is_nxdomain),
            dnssec_status: dnssec_status.and_then(CachedDnssecStatus::to_domain),
            cname_chain,
            upstream_server: None,
            upstream_pool: None,
            min_ttl,
            negative_soa_ttl: None,
            upstream_wire_data,
        })
    }

    fn check_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        let view = self.view(&query.domain, query.group_id);
        self.check_cache_str(query.domain.as_ref(), query.record_type, view)
    }

    fn insert_negative(&self, key: &CacheKey, ttl: u32, local_dns: bool) {
        self.cache.insert(
            borrowed(key),
            CachedData::NegativeResponse,
            ttl,
            Some(CachedDnssecStatus::Insecure),
            local_dns,
        );
    }

    /// Stores `resolution` under `key`. `routed` says a conditional pool
    /// answered it.
    fn store_in_cache(
        &self,
        query: &DnsQuery,
        key: &CacheKey,
        routed: bool,
        resolution: &DnsResolution,
    ) {
        // Never cache an unvalidated (Bogus/Indeterminate) result. Under Strict it
        // must SERVFAIL on every query, so the fast cache path must not be able to
        // serve it; under Permissive, re-validating it each time is fine.
        if resolution
            .dnssec_status
            .is_some_and(|status| status.is_unvalidated())
        {
            return;
        }
        let dnssec_status = resolution
            .dnssec_status
            .map_or(CachedDnssecStatus::Unknown, CachedDnssecStatus::from);

        if resolution.addresses.is_empty() {
            match &resolution.upstream_wire_data {
                // No answer records means NXDOMAIN or NODATA, which lives for
                // the SOA's negative TTL rather than the default one.
                Some(wire_data) => self.cache.insert(
                    borrowed(key),
                    CachedData::WireData(wire_data.clone()),
                    resolution.min_ttl.map_or_else(
                        || negative_ttl(resolution.negative_soa_ttl),
                        |ttl| ttl.max(1),
                    ),
                    Some(dnssec_status),
                    resolution.local_dns,
                ),
                None => self.insert_negative(
                    key,
                    resolution.negative_soa_ttl.unwrap_or(MIN_NEGATIVE_TTL),
                    resolution.local_dns,
                ),
            }
            return;
        }

        let ttl = resolution.min_ttl.unwrap_or(self.cache_ttl);
        self.cache.insert(
            borrowed(key),
            CachedData::IpAddresses(CachedAddresses {
                addresses: Arc::clone(&resolution.addresses),
            }),
            ttl,
            Some(dnssec_status),
            resolution.local_dns,
        );

        // Also cache the chain's final target under its own name, so a direct
        // query for it does not go upstream. `min_ttl` already spans the whole
        // chain, and the DNSSEC status is inherited, never elevated.
        // Not when a conditional pool answered: the target is another name,
        // which that pool does not answer for everyone.
        //
        // TODO(bailiwick): the response parser accepts any CNAME target, so an
        // untrusted upstream could plant a cross-bailiwick target here.
        if let Some(final_target) = resolution.cname_chain.last().filter(|_| !routed) {
            let target_name: &str = final_target.as_ref();
            // Cache keys are case-insensitive, so a case-variant self-loop
            // would write the same entry twice. A local name is configuration:
            // an upstream chain ending in it must not repoint it.
            if !target_name.eq_ignore_ascii_case(query.domain.as_ref())
                && self
                    .cache
                    .local_record_status(target_name, &query.record_type)
                    == LocalRecordStatus::NotLocal
            {
                let target = CacheKey::new(target_name, query.record_type);
                self.cache.insert(
                    borrowed(&target),
                    CachedData::IpAddresses(CachedAddresses {
                        addresses: Arc::clone(&resolution.addresses),
                    }),
                    ttl,
                    Some(dnssec_status),
                    resolution.local_dns,
                );
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
        // The leader sends at most once and then drops the sender, so after
        // this wait the channel holds its final word either way.
        let _ = rx.changed().await;
        if let Some(result) = rx.borrow().as_ref() {
            return Ok(result.to_resolution());
        }

        if let Some(cached) = self.check_cache(query) {
            return Self::cached_outcome(cached);
        }

        self.resolve(query).await
    }

    async fn resolve_as_leader(
        &self,
        query: &DnsQuery,
        key: CacheKey,
        routed: bool,
    ) -> Result<DnsResolution, DomainError> {
        let mut guard = InflightLeaderGuard {
            inflight: &self.inflight,
            key,
            defused: false,
        };

        // Another leader may have filled the cache between our election and
        // now; serve that and hand it to our followers instead of going upstream.
        if let Some(cached) =
            self.check_cache_str(query.domain.as_ref(), query.record_type, guard.key.view)
        {
            self.publish_inflight(&guard.key, &cached);
            guard.defuse();
            return Self::cached_outcome(cached);
        }

        let result = self.inner.resolve(query).await;

        match &result {
            Ok(resolution) => {
                self.store_in_cache(query, &guard.key, routed, resolution);
                self.publish_inflight(&guard.key, resolution);
                guard.defuse();
            }
            // Only an authoritative "no such name" is safe to cache: a
            // transient failure cached as NXDOMAIN would outlive the outage by
            // the whole negative TTL. The guard releases the followers.
            Err(DomainError::NxDomain) => self.insert_negative(&guard.key, MIN_NEGATIVE_TTL, false),
            Err(DomainError::LocalNxDomain) => {
                self.insert_negative(&guard.key, MIN_NEGATIVE_TTL, true);
            }
            Err(_) => self.cache.record_transient_upstream_error(),
        }

        result
    }

    /// A cache hit as `resolve` reports it: a negative entry is an error, which
    /// keeps saying whether the local DNS server gave it.
    fn cached_outcome(cached: DnsResolution) -> Result<DnsResolution, DomainError> {
        if cached.has_response_data() {
            Ok(cached)
        } else if cached.local_nxdomain {
            Err(DomainError::LocalNxDomain)
        } else {
            Err(DomainError::NxDomain)
        }
    }

    /// Removes the in-flight entry for `key` and publishes `resolution` to its
    /// followers. A resolution without response data is published as `None`,
    /// which followers turn into their own cache check or resolution.
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
            local_dns: resolution.local_dns,
            upstream_nxdomain: resolution.upstream_nxdomain,
            cname_chain: Arc::clone(&resolution.cname_chain),
            dnssec_status: resolution.dnssec_status,
            min_ttl: resolution.min_ttl,
            upstream_wire_data: resolution.upstream_wire_data.clone(),
        });
        let _ = tx.send(Some(inflight));
    }
}

#[async_trait]
impl DnsResolver for CachedResolver {
    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        self.check_cache(query)
    }

    fn try_cache_str(
        &self,
        domain: &str,
        record_type: RecordType,
        group_id: Option<i64>,
    ) -> Option<DnsResolution> {
        let view = self.view(domain, group_id);
        self.check_cache_str(domain, record_type, view)
    }

    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        // No cache probe before registering: callers probe with `try_cache`
        // first, and the leader re-checks once its guard is in place, which is
        // also what closes the race with a leader that just finished.
        let route = self.route(query);
        let view = route.map_or(0, |route| route.view);
        let key = CacheKey::new(query.domain.as_ref(), query.record_type).in_view(view);
        let (is_leader, rx) = self.register_or_join_inflight(&key);

        if !is_leader {
            return self.resolve_as_follower(query, rx).await;
        }
        self.resolve_as_leader(query, key, route.is_some()).await
    }
}

fn borrowed(key: &CacheKey) -> BorrowedKey<'_> {
    BorrowedKey::new(key.domain.as_str(), key.record_type).in_view(key.view)
}
