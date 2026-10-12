//! The cache operations the refresh scheduling and the L1 hit accounting
//! touch, measured in isolation: an L1 hit on one thread and on eight threads
//! sharing one hot name, an L2 hit, an insert, and the refresh maintenance a
//! 200k-entry cache costs.

use criterion::{criterion_group, criterion_main, Criterion};
use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, EvictionStrategy, RefreshScanOptions,
};
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

const HOT_NAME: &str = "www.example.com";
const L2_NAME: &str = "alias.example.com";
const CONTENDED_THREADS: u64 = 8;
const MAINTENANCE_ENTRIES: usize = 200_000;
const INSERT_NAMES: usize = 100_000;

fn cache(max_entries: usize) -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
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
        refresh_sample_rate: 1.0,
        min_ttl: 0,
        max_ttl: 86_400,
    }))
}

fn address() -> CachedData {
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14))]),
    })
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

    let insert_cache = self::cache(MAINTENANCE_ENTRIES);
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
    group.finish();
}

/// What keeping a 200k-entry cache renewed costs per maintenance cycle, with
/// nothing due yet: the part that grows with the cache, not with the work.
fn refresh_maintenance(c: &mut Criterion) {
    coarse_clock::tick();
    let cache = cache(MAINTENANCE_ENTRIES);
    for i in 0..MAINTENANCE_ENTRIES {
        cache.insert(
            &format!("m-{i}.example.com"),
            RecordType::A,
            address(),
            3600,
            None,
        );
    }
    let opts = RefreshScanOptions {
        min_lead_secs: 120,
        min_hit_rate: 2.0,
        min_frequency: 10,
    };
    assert!(cache.get_refresh_candidates(&opts).is_empty());

    let mut group = c.benchmark_group("cache_maintenance");
    group.sample_size(10);
    group.bench_function("refresh_cycle_200k", |b| {
        b.iter(|| cache.get_refresh_candidates(&opts))
    });
    group.finish();
}

criterion_group!(benches, cache_hits, refresh_maintenance);
criterion_main!(benches);
