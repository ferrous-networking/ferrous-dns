use crate::ports::{
    BlockFilterEnginePort, ClientRepository, DnsResolution, DnsResolver, FilterDecision,
    QueryLogRepository,
};
use ferrous_dns_domain::{
    BlockSource, DnsQuery, DnsRequest, DomainError, QueryLog, QuerySource, RecordType,
};
use lru::LruCache;
use std::cell::RefCell;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

const LAST_SEEN_CAPACITY: usize = 8_192;

thread_local! {
    static LAST_SEEN_TRACKER: RefCell<LruCache<IpAddr, u64>> =
        RefCell::new(LruCache::new(NonZeroUsize::new(LAST_SEEN_CAPACITY).unwrap()));
}

#[cfg(target_os = "linux")]
#[inline]
fn coarse_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_COARSE, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[cfg(not(target_os = "linux"))]
#[inline]
fn coarse_now_ns() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

pub struct HandleDnsQueryUseCase {
    resolver: Arc<dyn DnsResolver>,
    block_filter: Arc<dyn BlockFilterEnginePort>,
    query_log: Arc<dyn QueryLogRepository>,
    client_repo: Option<Arc<dyn ClientRepository>>,
    client_tracking_interval: Duration,
}

impl HandleDnsQueryUseCase {
    pub fn new(
        resolver: Arc<dyn DnsResolver>,
        block_filter: Arc<dyn BlockFilterEnginePort>,
        query_log: Arc<dyn QueryLogRepository>,
    ) -> Self {
        Self {
            resolver,
            block_filter,
            query_log,
            client_repo: None,
            client_tracking_interval: Duration::from_secs(60),
        }
    }

    pub fn with_client_tracking(
        mut self,
        client_repo: Arc<dyn ClientRepository>,
        interval_secs: u64,
    ) -> Self {
        self.client_repo = Some(client_repo);
        self.client_tracking_interval = Duration::from_secs(interval_secs);
        self
    }

    fn log(&self, query_log: &QueryLog) {
        if let Err(e) = self.query_log.log_query_sync(query_log) {
            tracing::warn!(error = %e, domain = %query_log.domain, "Failed to log query");
        }
    }

    fn base_query_log(request: &DnsRequest, response_time_us: u64, group_id: i64) -> QueryLog {
        QueryLog {
            id: None,
            domain: Arc::clone(&request.domain),
            record_type: request.record_type,
            client_ip: request.client_ip,
            client_hostname: None,
            blocked: false,
            response_time_us: Some(response_time_us),
            cache_hit: false,
            cache_refresh: false,
            dnssec_status: None,
            upstream_server: None,
            response_status: Some("NOERROR"),
            timestamp: None,
            query_source: QuerySource::Client,
            group_id: Some(group_id),
            block_source: None,
        }
    }

    fn maybe_track_client(&self, client_ip: IpAddr) {
        let Some(client_repo) = &self.client_repo else {
            return;
        };

        let now_ns = coarse_now_ns();
        let interval_ns = self.client_tracking_interval.as_nanos() as u64;
        let needs_update = LAST_SEEN_TRACKER.with(|t| {
            let mut tracker = t.borrow_mut();
            match tracker.peek(&client_ip) {
                Some(&last_ns) if now_ns.saturating_sub(last_ns) < interval_ns => false,
                _ => {
                    tracker.put(client_ip, now_ns);
                    true
                }
            }
        });

        if needs_update {
            let client_repo = Arc::clone(client_repo);
            tokio::spawn(async move {
                if let Err(e) = client_repo.update_last_seen(client_ip).await {
                    tracing::warn!(error = %e, ip = %client_ip, "Failed to track client");
                }
            });
        }
    }

    fn blocked_cname(&self, cname_chain: &[Arc<str>], group_id: i64) -> Option<BlockSource> {
        cname_chain
            .iter()
            .find(|domain| {
                matches!(
                    self.block_filter.check(domain, group_id),
                    FilterDecision::Block(_)
                )
            })
            .map(|_| BlockSource::CnameCloaking)
    }

    pub fn try_cache_direct(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
    ) -> Option<(Arc<Vec<IpAddr>>, u32)> {
        let start = Instant::now();
        let domain_arc: Arc<str> = Arc::from(domain);
        let group_id = self.block_filter.resolve_group(client_ip);

        if let FilterDecision::Block(_) = self.block_filter.check(domain, group_id) {
            return None;
        }

        let query = DnsQuery::new(Arc::clone(&domain_arc), record_type);
        let resolution = self.resolver.try_cache(&query)?;
        if resolution.addresses.is_empty() {
            return None;
        }

        self.log(&QueryLog {
            id: None,
            domain: domain_arc,
            record_type,
            client_ip,
            client_hostname: None,
            blocked: false,
            response_time_us: Some(start.elapsed().as_micros() as u64),
            cache_hit: true,
            cache_refresh: false,
            dnssec_status: resolution.dnssec_status,
            upstream_server: None,
            response_status: Some("NOERROR"),
            timestamp: None,
            query_source: QuerySource::Client,
            group_id: Some(group_id),
            block_source: None,
        });

        Some((resolution.addresses, resolution.min_ttl.unwrap_or(60)))
    }

    pub async fn execute(&self, request: &DnsRequest) -> Result<DnsResolution, DomainError> {
        let start = Instant::now();
        let elapsed_us = || start.elapsed().as_micros() as u64;

        self.maybe_track_client(request.client_ip);

        let dns_query = DnsQuery::new(Arc::clone(&request.domain), request.record_type);
        let group_id = self.block_filter.resolve_group(request.client_ip);

        if let FilterDecision::Block(block_source) =
            self.block_filter.check(&request.domain, group_id)
        {
            self.log(&QueryLog {
                blocked: true,
                response_status: Some("BLOCKED"),
                block_source: Some(block_source),
                ..Self::base_query_log(request, elapsed_us(), group_id)
            });
            return Err(DomainError::Blocked);
        }

        if let Some(cached) = self.resolver.try_cache(&dns_query) {
            if !cached.addresses.is_empty() {
                self.log(&QueryLog {
                    cache_hit: true,
                    dnssec_status: cached.dnssec_status,
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                return Ok(cached);
            } else if cached.cache_hit {
                self.log(&QueryLog {
                    cache_hit: true,
                    response_status: Some("NXDOMAIN"),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                return Err(DomainError::NxDomain);
            }
        }

        match self.resolver.resolve(&dns_query).await {
            Ok(resolution) => {
                if let Some(block_source) = self.blocked_cname(&resolution.cname_chain, group_id) {
                    let ttl = resolution.min_ttl.map(|t| t as u64).unwrap_or(60).max(5);
                    self.block_filter
                        .store_cname_decision(&request.domain, group_id, ttl);
                    self.log(&QueryLog {
                        blocked: true,
                        response_status: Some("BLOCKED"),
                        block_source: Some(block_source),
                        ..Self::base_query_log(request, elapsed_us(), group_id)
                    });
                    return Err(DomainError::Blocked);
                }
                let response_status = if resolution.local_dns {
                    Some("LOCAL_DNS")
                } else {
                    Some("NOERROR")
                };
                self.log(&QueryLog {
                    cache_hit: resolution.cache_hit,
                    dnssec_status: resolution.dnssec_status,
                    upstream_server: resolution.upstream_server.clone(),
                    response_status,
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                Ok(resolution)
            }
            Err(DomainError::LocalNxDomain) => {
                self.log(&QueryLog {
                    response_status: Some("LOCAL_DNS"),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                Err(DomainError::NxDomain)
            }
            Err(e) => {
                let response_status = match &e {
                    DomainError::NxDomain => "NXDOMAIN",
                    DomainError::QueryTimeout => "TIMEOUT",
                    _ => "SERVFAIL",
                };
                self.log(&QueryLog {
                    response_status: Some(response_status),
                    ..Self::base_query_log(request, elapsed_us(), group_id)
                });
                Err(e)
            }
        }
    }
}
