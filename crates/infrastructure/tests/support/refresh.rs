//! Fixtures for the refresh tests: a cache wired to a running worker, or to
//! an inbox the test reads in its place, and waits with a deadline so a hang
//! fails the test instead of blocking it.
#![allow(dead_code)]

use ferrous_dns_application::ports::DnsResolver;
use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, ColdThresholds, DnsCache, DnsCacheConfig, DnsCacheMaintenance,
    EvictionStrategy, RefreshRequest, RefreshSenders, ScheduledRefresh, TimerInbox,
};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub const OLD_IP: &str = "192.0.2.1";
pub const NEW_IP: &str = "192.0.2.2";

pub fn refresh_cache(
    max_entries: usize,
    refresh_threshold: f64,
    access_window_secs: u64,
) -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold,
        batch_eviction_percentage: 0.2,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
    }))
}

pub fn address(ip: &str) -> CachedData {
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![ip.parse::<IpAddr>().unwrap()]),
    })
}

/// A CNAME never enters L1, so every lookup of it is an L2 hit and counts.
pub fn cname() -> CachedData {
    CachedData::CanonicalName(Arc::from("target.example"))
}

/// Thresholds that rank nothing as cold.
pub fn no_ranking() -> ColdThresholds {
    ColdThresholds {
        min_hit_rate: 0.0,
        min_frequency: 0,
    }
}

/// The two ways into a running worker.
pub struct Worker {
    pub stale: mpsc::Sender<RefreshRequest>,
    pub timers: Arc<TimerInbox>,
}

/// Wires `cache` to a new worker over `resolver`, as the cli wiring does,
/// and keeps the coarse clock ticking. With `optimistic` off nothing arms a
/// timer, and only serve-stale repairs reach the worker.
pub fn start_worker(
    cache: &Arc<DnsCache>,
    resolver: Arc<dyn DnsResolver>,
    thresholds: ColdThresholds,
    optimistic: bool,
) -> Worker {
    let _ticker = coarse_clock::start_clock_ticker();
    let (stale, stale_rx) = mpsc::channel(128);
    let timers = Arc::new(TimerInbox::new(4_096));
    let wired = optimistic.then(|| Arc::clone(&timers));
    cache.set_refresh_senders(RefreshSenders {
        stale: stale.clone(),
        timers: wired.clone(),
    });
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(cache),
        resolver,
        None,
        stale_rx,
        wired,
        thresholds,
    );
    Worker { stale, timers }
}

/// Wires `cache` to an inbox and a repair queue the test reads in place of
/// a worker. `capacity` bounds each inbox shard.
pub fn wire_timers(
    cache: &DnsCache,
    capacity: usize,
) -> (Arc<TimerInbox>, mpsc::Receiver<RefreshRequest>) {
    let (stale, stale_rx) = mpsc::channel(16);
    let inbox = Arc::new(TimerInbox::new(capacity));
    cache.set_refresh_senders(RefreshSenders {
        stale,
        timers: Some(Arc::clone(&inbox)),
    });
    (inbox, stale_rx)
}

/// Every timer armed since the last drain.
pub fn drain(inbox: &TimerInbox) -> Vec<ScheduledRefresh> {
    let mut timers = Vec::new();
    inbox.drain(|timer| timers.push(timer));
    timers
}

/// Polls `done` every 10 ms for up to `within`.
pub async fn wait_until(within: Duration, done: impl Fn() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while !done() {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

/// What L2 holds for `domain` A, read on a fresh thread so this thread's L1
/// copy cannot answer instead.
pub fn cached_addresses(cache: &Arc<DnsCache>, domain: &str) -> Option<Vec<IpAddr>> {
    let cache = Arc::clone(cache);
    let domain = domain.to_string();
    std::thread::spawn(move || {
        cache
            .get(&domain, &RecordType::A)
            .and_then(|(data, _, _, _)| data.as_ip_addresses().map(|a| a.as_ref().clone()))
    })
    .join()
    .unwrap()
}
