use super::super::cache::key::CacheKey;
use super::super::cache::{
    CachedAddresses, CachedData, DnsCacheAccess, DnssecStatus, NegativeQueryTracker,
};
use super::super::prefetch::PrefetchPredictor;
use async_trait::async_trait;
use dashmap::DashMap;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver, EMPTY_CNAME_CHAIN};
use std::sync::LazyLock;

static EMPTY_ADDRESSES: LazyLock<Arc<Vec<IpAddr>>> = LazyLock::new(|| Arc::new(vec![]));
use ferrous_dns_domain::{DnsQuery, DomainError};
use hickory_proto::rr::{RData, Record};
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::debug;

struct InflightResult {
    addresses: Arc<Vec<IpAddr>>,
    cname_chain: Arc<[Arc<str>]>,
    dnssec_status: Option<&'static str>,
    min_ttl: Option<u32>,
}

type InflightSender = Arc<watch::Sender<Option<Arc<InflightResult>>>>;

struct InflightLeaderGuard {
    inflight: Arc<DashMap<CacheKey, InflightSender, FxBuildHasher>>,
    key: CacheKey,
}

impl Drop for InflightLeaderGuard {
    fn drop(&mut self) {
        if let Some((_, tx)) = self.inflight.remove(&self.key) {
            let _ = tx.send(None);
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
    ) -> Self {
        Self {
            inner,
            cache,
            cache_ttl,
            negative_ttl_tracker,
            prefetch_predictor: None,
            inflight: Arc::new(DashMap::with_hasher(FxBuildHasher)),
        }
    }

    pub fn with_prefetch(mut self, predictor: Arc<PrefetchPredictor>) -> Self {
        self.prefetch_predictor = Some(predictor);
        self
    }

    fn check_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        self.cache.get(&query.domain, &query.record_type).map(
            |(data, dnssec_status, remaining_ttl)| {
                debug!(
                    domain = %query.domain,
                    record_type = %query.record_type,
                    "Cache HIT"
                );

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
                        authority_records: vec![],
                    },
                    CachedData::CanonicalName(_) => DnsResolution {
                        addresses: Arc::clone(&EMPTY_ADDRESSES),
                        cache_hit: true,
                        local_dns: false,
                        dnssec_status: dnssec_str,
                        cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
                        upstream_server: None,
                        upstream_pool: None,
                        min_ttl: remaining_ttl,
                        authority_records: vec![],
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
                        authority_records: vec![],
                    },
                }
            },
        )
    }

    fn insert_negative(&self, query: &DnsQuery, authority_records: &[Record]) {
        let ttl = extract_negative_ttl(authority_records)
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

    fn store_in_cache(&self, query: &DnsQuery, resolution: &DnsResolution) {
        if resolution.addresses.is_empty() {
            self.insert_negative(query, &resolution.authority_records);
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
                    authority_records: vec![],
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
                authority_records: vec![],
            });
        }

        if let Some(cached) = self.check_cache(query) {
            return if cached.addresses.is_empty() {
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
        debug!(
            domain = %query.domain,
            record_type = %query.record_type,
            "Cache MISS"
        );

        let guard = InflightLeaderGuard {
            inflight: Arc::clone(&self.inflight),
            key: key.clone(),
        };

        let result = self.inner.resolve(query).await;

        match &result {
            Ok(resolution) => {
                self.store_in_cache(query, resolution);
                if let Some((_, tx)) = self.inflight.remove(&key) {
                    let inflight = Arc::new(InflightResult {
                        addresses: Arc::clone(&resolution.addresses),
                        cname_chain: Arc::clone(&resolution.cname_chain),
                        dnssec_status: resolution.dnssec_status,
                        min_ttl: resolution.min_ttl,
                    });
                    let _ = tx.send(Some(inflight));
                }
            }
            Err(_) => {
                self.insert_negative(query, &[]);
                if let Some((_, tx)) = self.inflight.remove(&key) {
                    let _ = tx.send(None);
                }
            }
        }

        drop(guard);
        result
    }
}

#[async_trait]
impl DnsResolver for CachedResolver {
    fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
        self.check_cache(query)
    }

    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        if let Some(cached) = self.check_cache(query) {
            return if cached.addresses.is_empty() {
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

        self.resolve_as_leader(query, key).await
    }
}

fn extract_negative_ttl(authority_records: &[Record]) -> Option<u32> {
    authority_records.iter().find_map(|r| {
        if let RData::SOA(soa) = r.data() {
            Some(soa.minimum().min(r.ttl()))
        } else {
            None
        }
    })
}

fn clamp_negative_ttl(ttl: u32) -> u32 {
    const MIN_NEGATIVE_TTL: u32 = 30;
    const MAX_NEGATIVE_TTL: u32 = 3_600;
    ttl.clamp(MIN_NEGATIVE_TTL, MAX_NEGATIVE_TTL)
}
