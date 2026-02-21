use super::super::cache::key::CacheKey;
use super::super::cache::{CachedData, DnsCacheAccess, DnssecStatus, NegativeQueryTracker};
use super::super::prefetch::PrefetchPredictor;
use async_trait::async_trait;
use dashmap::DashMap;
use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError};
use rustc_hash::FxBuildHasher;
use std::sync::Arc;
use tokio::sync::watch;
use tracing::debug;

type InflightSender = Arc<watch::Sender<Option<Arc<DnsResolution>>>>;

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
                    CachedData::IpAddresses(addrs) => DnsResolution {
                        addresses: Arc::clone(&addrs),
                        cache_hit: true,
                        dnssec_status: dnssec_str,
                        cname: None,
                        upstream_server: None,
                        min_ttl: remaining_ttl,
                        authority_records: vec![],
                    },
                    CachedData::CanonicalName(_) => DnsResolution {
                        addresses: Arc::new(vec![]),
                        cache_hit: true,
                        dnssec_status: dnssec_str,
                        cname: None,
                        upstream_server: None,
                        min_ttl: remaining_ttl,
                        authority_records: vec![],
                    },
                    CachedData::NegativeResponse => DnsResolution {
                        addresses: Arc::new(vec![]),
                        cache_hit: true,
                        dnssec_status: dnssec_str,
                        cname: None,
                        upstream_server: None,
                        min_ttl: remaining_ttl,
                        authority_records: vec![],
                    },
                }
            },
        )
    }

    fn insert_negative(&self, query: &DnsQuery) {
        let dynamic_ttl = self.negative_ttl_tracker.record_and_get_ttl(&query.domain);
        self.cache.insert(
            query.domain.as_ref(),
            query.record_type,
            CachedData::NegativeResponse,
            dynamic_ttl,
            Some(DnssecStatus::Insecure),
        );
    }

    fn store_in_cache(&self, query: &DnsQuery, resolution: &DnsResolution) {
        if resolution.addresses.is_empty() {
            self.insert_negative(query);
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
                CachedData::IpAddresses(addresses),
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
    ) -> (bool, watch::Receiver<Option<Arc<DnsResolution>>>) {
        match self.inflight.entry(key.clone()) {
            dashmap::Entry::Occupied(e) => {
                let rx = e.get().subscribe();
                drop(e);
                (false, rx)
            }
            dashmap::Entry::Vacant(e) => {
                let (tx, rx) = watch::channel(None::<Arc<DnsResolution>>);
                e.insert(Arc::new(tx));
                (true, rx)
            }
        }
    }

    async fn resolve_as_follower(
        &self,
        query: &DnsQuery,
        mut rx: watch::Receiver<Option<Arc<DnsResolution>>>,
    ) -> Result<DnsResolution, DomainError> {
        if let Ok(()) = rx.changed().await {
            if let Some(arc_res) = rx.borrow().clone() {
                return Ok(DnsResolution {
                    addresses: Arc::clone(&arc_res.addresses),
                    cache_hit: false,
                    dnssec_status: arc_res.dnssec_status,
                    cname: None,
                    upstream_server: None,
                    min_ttl: arc_res.min_ttl,
                    authority_records: vec![],
                });
            }
        }

        if let Some(arc_res) = rx.borrow().clone() {
            return Ok(DnsResolution {
                addresses: Arc::clone(&arc_res.addresses),
                cache_hit: false,
                dnssec_status: arc_res.dnssec_status,
                cname: None,
                upstream_server: None,
                min_ttl: arc_res.min_ttl,
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

        match self.inner.resolve(query).await {
            Ok(r) => {
                self.store_in_cache(query, &r);
                Ok(r)
            }
            Err(e) => Err(e),
        }
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

        let result = self.inner.resolve(query).await;

        match &result {
            Ok(resolution) => {
                self.store_in_cache(query, resolution);
                if let Some((_, tx)) = self.inflight.remove(&key) {
                    let _ = tx.send(Some(Arc::new(resolution.clone())));
                }
            }
            Err(_) => {
                self.insert_negative(query);
                self.inflight.remove(&key);
            }
        }

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
