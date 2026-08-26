use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::{
    CachedData, DnsCache, DnsCacheConfig, EvictionStrategy, RefreshRequest, RefreshScanOptions,
    RefreshSenders,
};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::mpsc;

fn create_stale_cache() -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
        min_threshold: 0.0,
        refresh_threshold: 0.0,
        batch_eviction_percentage: 0.2,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
        min_ttl: 0,
        max_ttl: 86_400,
    })
}

fn make_cname_data(name: &str) -> CachedData {
    CachedData::CanonicalName(Arc::from(name))
}

/// Wires only the stale queue, which is the one serve-stale hits feed. The
/// optimistic sender is still required, so it gets a receiver the test keeps
/// alive by returning it.
fn wire_stale_queue(
    cache: &DnsCache,
    capacity: usize,
) -> (
    mpsc::Receiver<RefreshRequest>,
    mpsc::Receiver<RefreshRequest>,
) {
    let (stale_tx, stale_rx) = mpsc::channel(capacity);
    let (optimistic_tx, optimistic_rx) = mpsc::channel(capacity);
    cache.set_refresh_senders(RefreshSenders {
        stale: stale_tx,
        optimistic: optimistic_tx,
    });
    (stale_rx, optimistic_rx)
}

#[test]
fn test_stale_entry_sends_to_refresh_channel() {
    let cache = create_stale_cache();
    let (mut rx, _optimistic_rx) = wire_stale_queue(&cache, 16);

    cache.insert(
        "stale-chan.com",
        RecordType::CNAME,
        make_cname_data("alias.stale-chan.com"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_millis(1200));
    coarse_clock::tick();

    let result = cache.get(&Arc::from("stale-chan.com"), &RecordType::CNAME);
    if result.is_none() {
        return;
    }

    let msg = rx.try_recv();
    assert!(msg.is_ok(), "Stale hit must send domain to refresh channel");
    let (domain, record_type) = msg.unwrap();
    assert_eq!(&*domain, "stale-chan.com");
    assert_eq!(record_type, RecordType::CNAME);

    let stale_hits = cache.metrics().stale_hits.load(Ordering::Relaxed);
    assert!(
        stale_hits >= 1,
        "stale_hits metric must be incremented; got {stale_hits}"
    );
}

#[test]
fn test_stale_refresh_only_fires_once() {
    let cache = create_stale_cache();
    let (mut rx, _optimistic_rx) = wire_stale_queue(&cache, 16);

    cache.insert(
        "once.com",
        RecordType::CNAME,
        make_cname_data("alias.once.com"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_millis(1200));
    coarse_clock::tick();

    let r1 = cache.get(&Arc::from("once.com"), &RecordType::CNAME);
    let r2 = cache.get(&Arc::from("once.com"), &RecordType::CNAME);
    let r3 = cache.get(&Arc::from("once.com"), &RecordType::CNAME);

    if r1.is_none() {
        return;
    }

    assert!(r2.is_some(), "Subsequent stale gets must still return data");
    assert!(r3.is_some(), "Subsequent stale gets must still return data");

    let mut count = 0;
    while rx.try_recv().is_ok() {
        count += 1;
    }
    assert_eq!(
        count, 1,
        "CAS must ensure only 1 refresh message is sent; got {count}"
    );
}

#[test]
fn test_stale_refresh_channel_full_does_not_block() {
    let cache = create_stale_cache();
    let (_rx, _optimistic_rx) = wire_stale_queue(&cache, 1);

    cache.insert(
        "full-a.com",
        RecordType::CNAME,
        make_cname_data("alias.full-a.com"),
        1,
        None,
    );
    cache.insert(
        "full-b.com",
        RecordType::CNAME,
        make_cname_data("alias.full-b.com"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_millis(1200));
    coarse_clock::tick();

    let r1 = cache.get(&Arc::from("full-a.com"), &RecordType::CNAME);
    if r1.is_none() {
        return;
    }

    let r2 = cache.get(&Arc::from("full-b.com"), &RecordType::CNAME);
    assert!(
        r2.is_some(),
        "get() must not block even when the refresh channel is full"
    );
}

#[test]
fn test_stale_get_without_sender_still_works() {
    let cache = create_stale_cache();

    cache.insert(
        "no-sender.com",
        RecordType::CNAME,
        make_cname_data("alias.no-sender.com"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_millis(1200));
    coarse_clock::tick();

    let result = cache.get(&Arc::from("no-sender.com"), &RecordType::CNAME);
    if let Some((_, _, Some(ttl))) = result {
        assert!(
            ttl >= 1,
            "Stale entry must return valid TTL even without sender; got {ttl}"
        );
    }
}

#[test]
fn test_expired_beyond_grace_not_served_stale() {
    let cache = create_stale_cache();
    let (_rx, _optimistic_rx) = wire_stale_queue(&cache, 16);

    cache.insert(
        "expired.com",
        RecordType::CNAME,
        make_cname_data("alias.expired.com"),
        1,
        None,
    );

    // TTL=1, grace=2×TTL=2s from insert. Sleep 3s to exceed the grace period.
    std::thread::sleep(std::time::Duration::from_millis(3000));
    coarse_clock::tick();

    let result = cache.get(&Arc::from("expired.com"), &RecordType::CNAME);
    assert!(
        result.is_none(),
        "Entry expired beyond grace period must not be served"
    );
}

#[test]
fn test_queued_for_optimistic_still_schedules_stale_repair() {
    // Uma entrada reivindicada por uma varredura de manutenção pode ficar na
    // fila optimistic por boa parte de um ciclo. Enquanto espera, um cliente
    // que a encontra stale precisa conseguir agendar o reparo rápido pelo canal
    // não pausado — é para isso que a flag de fila é separada da flag de voo.
    // Com uma flag só, `try_set_refreshing` falhava e o reparo nunca era
    // enfileirado: o cliente recebia stale com TTL 2, voltava a perguntar, e a
    // entrada morria no fim do grace period.
    let cache = create_stale_cache();
    let (mut stale_rx, _optimistic_rx) = wire_stale_queue(&cache, 16);

    // TTL 3 (grace = 6 s) em vez de 1: o relógio grosseiro é global e outros
    // testes do binário chamam `tick()` em paralelo, então uma janela de 2 s
    // deixa pouca folga se esta thread for desescalonada entre o sleep e a
    // varredura. Em 3,2 s a entrada está expirada com quase 3 s de folga.
    cache.insert(
        "queued-stale.com",
        RecordType::CNAME,
        make_cname_data("alias.queued-stale.com"),
        3,
        None,
    );

    std::thread::sleep(std::time::Duration::from_millis(3200));
    coarse_clock::tick();

    // A varredura reivindica a entrada para a fila optimistic.
    let claimed = cache.get_refresh_candidates(&RefreshScanOptions {
        min_lead_secs: 0,
        min_hit_rate: 0.0,
        min_frequency: 0,
    });
    assert!(
        claimed.iter().any(|(d, _)| d == "queued-stale.com"),
        "PRECONDIÇÃO FALHOU: a varredura deveria ter reivindicado a entrada"
    );

    // Agora o cliente chega e encontra a entrada stale.
    let result = cache.get(&Arc::from("queued-stale.com"), &RecordType::CNAME);
    assert!(
        result.is_some(),
        "PRECONDIÇÃO FALHOU: a entrada deveria ser servida como stale"
    );

    let msg = stale_rx.try_recv();
    assert!(
        msg.is_ok(),
        "Entrada já reivindicada para a fila optimistic ainda deve poder agendar \
         o reparo serve-stale no canal rápido"
    );
    let (domain, record_type) = msg.expect("mensagem de reparo stale ausente");
    assert_eq!(&*domain, "queued-stale.com");
    assert_eq!(record_type, RecordType::CNAME);
}
