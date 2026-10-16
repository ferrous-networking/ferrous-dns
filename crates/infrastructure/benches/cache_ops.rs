//! The cache operations the refresh scheduling and the L1 hit accounting
//! touch, measured in isolation: an L1 hit on one thread and on eight threads
//! sharing one hot name, an L2 hit, an insert that arms its refresh timer,
//! one that arms its expiry instead (optimistic refresh off), the timer work
//! a 200k-entry cache costs per minute, and removing the entries that died in
//! it. `l2_hit_group_view` is an address answer in a client group's own view,
//! which L1 never holds.

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::cache::CacheKey;
use ferrous_dns_infrastructure::dns::{
    BorrowedKey, CachedAddresses, CachedData, ColdThresholds, DnsCache, DnsCacheAccess,
    DnsCacheConfig, EvictionStrategy, RefreshSchedule, ScheduledRefresh, TimerKind,
};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const HOT_NAME: &str = "www.example.com";
const L2_NAME: &str = "alias.example.com";
const GROUP_VIEW_NAME: &str = "host.corp.example";
const GROUP_VIEW: u32 = 3;
const CONTENDED_THREADS: u64 = 8;
const MAINTENANCE_ENTRIES: usize = 200_000;
const INSERT_NAMES: usize = 100_000;
/// The TTL every maintenance-bench entry has, so 200k timers spread over it.
const MAINTENANCE_TTL_SECS: u64 = 3600;
/// Entries that died in a 200k-entry cache, removed in one bench iteration.
const DEAD_ENTRIES: usize = 10_000;

fn cache(max_entries: usize) -> Arc<DnsCache> {
    Arc::new(DnsCache::new(config(max_entries)))
}

/// [`cache`] with optimistic refresh off: an entry's only timer is its expiry.
fn cache_without_renewal(max_entries: usize) -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        renew_ahead: false,
        ..config(max_entries)
    }))
}

fn config(max_entries: usize) -> DnsCacheConfig {
    DnsCacheConfig {
        max_entries,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.1,
        min_frequency: 10,
        min_lfuk_score: 1.5,
        shard_amount: 16,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
        renew_ahead: true,
        retry_lapsed_after_secs: 300,
    }
}

fn address() -> CachedData {
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14))]),
    })
}

/// Wires a refresh worker stand-in that collects timers in batches, as the
/// worker does on its tick, so an insert pays for arming its timer as in
/// production. It collects every millisecond rather than every second, so the
/// inbox stays as small as it would in production at a benchmark's insert rate.
fn wire_timer_drain(cache: &DnsCache) {
    let timers = Arc::clone(cache.timer_inbox());
    std::thread::spawn(move || loop {
        timers.drain(|timer| drop(black_box(timer)));
        std::thread::sleep(Duration::from_millis(1));
    });
}

/// Runs `iters` lookups of the hot name spread over `CONTENDED_THREADS`
/// threads, each with its own warm L1, and returns the wall time of the
/// slowest one: contention on shared state shows up as a longer wall time.
fn contended_l1_hits(cache: &Arc<DnsCache>, iters: u64) -> Duration {
    let per_thread = iters.div_ceil(CONTENDED_THREADS);
    let barrier = Arc::new(Barrier::new(CONTENDED_THREADS as usize));
    let threads: Vec<_> = (0..CONTENDED_THREADS)
        .map(|_| {
            let cache = Arc::clone(cache);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                assert!(cache.get(HOT_NAME, &RecordType::A).is_some());
                barrier.wait();
                let start = Instant::now();
                for _ in 0..per_thread {
                    black_box(cache.get(black_box(HOT_NAME), &RecordType::A));
                }
                start.elapsed()
            })
        })
        .collect();
    threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .max()
        .unwrap_or_default()
}

fn cache_hits(c: &mut Criterion) {
    coarse_clock::tick();
    let cache = cache(10_000);
    cache.insert(HOT_NAME, RecordType::A, address(), 3600, None);
    // A CNAME is never promoted to L1, so every lookup is an L2 hit.
    cache.insert(
        L2_NAME,
        RecordType::A,
        CachedData::CanonicalName(Arc::from(HOT_NAME)),
        3600,
        None,
    );
    assert!(cache.get(HOT_NAME, &RecordType::A).is_some());
    assert!(cache.get(L2_NAME, &RecordType::A).is_some());

    let mut group = c.benchmark_group("cache_ops");
    group.bench_function("l1_hit", |b| {
        b.iter(|| cache.get(black_box(HOT_NAME), &RecordType::A))
    });
    group.bench_function("l1_hit_8_threads", |b| {
        b.iter_custom(|iters| contended_l1_hits(&cache, iters))
    });
    group.bench_function("l2_hit", |b| {
        b.iter(|| cache.get(black_box(L2_NAME), &RecordType::A))
    });
    DnsCacheAccess::insert(
        cache.as_ref(),
        BorrowedKey::new(GROUP_VIEW_NAME, RecordType::A).in_view(GROUP_VIEW),
        address(),
        3600,
        None,
        true,
    );
    assert!(cache
        .get_in(GROUP_VIEW_NAME, &RecordType::A, GROUP_VIEW)
        .is_some());
    group.bench_function("l2_hit_group_view", |b| {
        b.iter(|| cache.get_in(black_box(GROUP_VIEW_NAME), &RecordType::A, GROUP_VIEW))
    });

    let insert_cache = self::cache(MAINTENANCE_ENTRIES);
    wire_timer_drain(&insert_cache);
    let names: Vec<String> = (0..INSERT_NAMES)
        .map(|i| format!("host-{i}.example.com"))
        .collect();
    let mut next = 0usize;
    group.bench_function("insert", |b| {
        b.iter(|| {
            let name = &names[next % names.len()];
            next += 1;
            insert_cache.insert(black_box(name), RecordType::A, address(), 3600, None);
        })
    });
    // Optimistic refresh off: the same insert, arming its expiry instead.
    let refresh_off_cache = cache_without_renewal(MAINTENANCE_ENTRIES);
    wire_timer_drain(&refresh_off_cache);
    group.bench_function("insert_refresh_off", |b| {
        b.iter(|| {
            let name = &names[next % names.len()];
            next += 1;
            refresh_off_cache.insert(black_box(name), RecordType::A, address(), 3600, None);
        })
    });
    group.finish();
}

/// What keeping a 200k-entry cache renewed costs per minute: the 60 ticks
/// that take the timers falling due in that minute, against a pass over all
/// 200k entries, which any scan for due entries would cost.
fn refresh_maintenance(c: &mut Criterion) {
    let keys: Vec<CacheKey> = (0..MAINTENANCE_ENTRIES)
        .map(|i| CacheKey::new(&format!("m-{i}.example.com"), RecordType::A))
        .collect();
    let full_schedule = || {
        let mut schedule = RefreshSchedule::default();
        for (i, key) in keys.iter().enumerate() {
            schedule.register(ScheduledRefresh {
                due_at_secs: i as u64 % MAINTENANCE_TTL_SECS,
                key: key.clone(),
                kind: TimerKind::Due,
            });
        }
        schedule
    };

    let mut group = c.benchmark_group("cache_maintenance");
    group.sample_size(10);
    group.bench_function("refresh_timers_minute_200k", |b| {
        b.iter_batched(
            full_schedule,
            |mut schedule| {
                for second in 0..60 {
                    black_box(schedule.take_due(second));
                }
                schedule
            },
            BatchSize::LargeInput,
        )
    });

    // Removing the `DEAD_ENTRIES` that died in a 200k-entry cache: each by the
    // timer it armed, which is all expiry costs. A pass over the whole cache
    // would cost the same `O(200k)` however few had died.
    let dead_cache = || {
        coarse_clock::tick();
        let cache = cache_without_renewal(MAINTENANCE_ENTRIES);
        for (i, key) in keys.iter().enumerate() {
            let ttl = if i < DEAD_ENTRIES { 1 } else { 3600 };
            cache.insert(&key.domain, RecordType::A, address(), ttl, None);
        }
        let mut timers = Vec::new();
        cache.timer_inbox().drain(|timer| timers.push(timer));
        timers.retain(|timer| timer.due_at_secs < coarse_clock::coarse_now_secs() + 3600);
        (cache, timers)
    };
    group.bench_function("expire_10k_dead_of_200k", |b| {
        b.iter_batched(
            dead_cache,
            |(cache, timers)| {
                let thresholds = ColdThresholds {
                    min_hit_rate: 0.0,
                    min_frequency: 0,
                };
                for timer in &timers {
                    let dead_at = timer.due_at_secs;
                    black_box(cache.claim_due_refresh(timer, dead_at, &thresholds));
                }
                assert_eq!(cache.len(), MAINTENANCE_ENTRIES - DEAD_ENTRIES);
                cache
            },
            BatchSize::LargeInput,
        )
    });
    group.finish();
}

criterion_group!(benches, cache_hits, refresh_maintenance);
criterion_main!(benches);
