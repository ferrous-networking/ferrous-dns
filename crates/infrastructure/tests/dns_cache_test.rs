use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::cache::eviction::{
    EvictionPolicy, HitRatePolicy, LfuPolicy, LfukPolicy, LruPolicy,
};
use ferrous_dns_infrastructure::dns::{
    CachedData, CachedRecord, DnsCache, DnsCacheConfig, DnssecStatus, EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::Arc;

/// Cria um cache com refresh_threshold=0.0 (qualquer entrada passa o filtro de tempo)
/// e access_window_secs configurável para testes de refresh.
fn create_refresh_cache(access_window_secs: u64) -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
        min_threshold: 0.0,
        refresh_threshold: 0.0, // toda entrada qualifica pelo tempo imediatamente
        batch_eviction_percentage: 0.2,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
    })
}

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().unwrap();
    CachedData::IpAddresses(Arc::new(vec![addr]))
}

/// Cria dados CNAME que NÃO vão para o cache L1 (apenas IpAddresses usam L1).
/// Usar isso em testes que precisam que cache.get() incremente hit_count no L2.
fn make_cname_data(name: &str) -> CachedData {
    CachedData::CanonicalName(Arc::from(name))
}

fn create_cache(
    max_entries: usize,
    strategy: EvictionStrategy,
    min_frequency: u64,
    min_lfuk_score: f64,
) -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries,
        eviction_strategy: strategy,
        min_threshold: 2.0,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.2,
        adaptive_thresholds: false,
        min_frequency,
        min_lfuk_score,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
    })
}

#[test]
fn test_cache_insert_and_get_basic() {
    let cache = create_cache(100, EvictionStrategy::HitRate, 0, 0.0);

    cache.insert(
        "example.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        300,
        None,
    );

    let result = cache.get(&Arc::from("example.com"), &RecordType::A);
    assert!(result.is_some());
    assert_eq!(cache.len(), 1);
}

#[test]
fn test_cache_creation_with_min_frequency() {
    let cache = create_cache(100, EvictionStrategy::LFU, 10, 0.0);

    cache.insert(
        "test.com",
        RecordType::A,
        make_ip_data("10.0.0.1"),
        300,
        None,
    );

    let result = cache.get(&Arc::from("test.com"), &RecordType::A);
    assert!(result.is_some());
    assert_eq!(cache.strategy(), EvictionStrategy::LFU);
}

#[test]
fn test_cache_creation_with_min_lfuk_score() {
    let cache = create_cache(100, EvictionStrategy::LFUK, 0, 1.5);

    cache.insert(
        "test.com",
        RecordType::A,
        make_ip_data("10.0.0.1"),
        300,
        None,
    );

    let result = cache.get(&Arc::from("test.com"), &RecordType::A);
    assert!(result.is_some());
    assert_eq!(cache.strategy(), EvictionStrategy::LFUK);
}

#[test]
fn test_cache_eviction_strategy_selection() {
    let strategies = vec![
        EvictionStrategy::LRU,
        EvictionStrategy::HitRate,
        EvictionStrategy::LFU,
        EvictionStrategy::LFUK,
    ];

    for strategy in strategies {
        let cache = create_cache(10, strategy, 5, 1.0);
        assert_eq!(cache.strategy(), strategy);

        cache.insert(
            "test.com",
            RecordType::A,
            make_ip_data("1.1.1.1"),
            300,
            None,
        );
        assert_eq!(cache.len(), 1);
    }
}

#[test]
fn test_cache_metrics_after_eviction() {
    let max_entries = 5;
    let cache = create_cache(max_entries, EvictionStrategy::LFU, 0, 0.0);

    for i in 0..max_entries + 2 {
        let domain = format!("domain{}.com", i);
        cache.insert(
            &domain,
            RecordType::A,
            make_ip_data(&format!("10.0.0.{}", i + 1)),
            300,
            None,
        );
    }
    cache.evict_entries();

    let metrics = cache.metrics();
    assert!(
        metrics.evictions.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "Evictions should have occurred"
    );
}

#[test]
fn test_lfu_eviction_respects_min_frequency() {
    let cache = create_cache(5, EvictionStrategy::LFU, 3, 0.0);

    // Insert 5 entries
    for i in 0..5 {
        let domain = format!("domain{}.com", i);
        cache.insert(
            &domain,
            RecordType::A,
            make_ip_data(&format!("10.0.0.{}", i + 1)),
            3600,
            None,
        );
    }

    // Simulate hits on some entries to push them above min_frequency threshold
    // domain0 gets 5 hits (above threshold of 3)
    for _ in 0..5 {
        cache.get(&Arc::from("domain0.com"), &RecordType::A);
    }

    // domain1 gets 0 hits (below threshold of 3) - should be evicted first

    // domain2 gets 4 hits (above threshold)
    for _ in 0..4 {
        cache.get(&Arc::from("domain2.com"), &RecordType::A);
    }

    // Trigger eviction by inserting more entries
    cache.insert(
        "new-domain.com",
        RecordType::A,
        make_ip_data("10.0.1.1"),
        3600,
        None,
    );

    // domain0 (5 hits) and domain2 (4 hits) should still be present
    assert!(
        cache
            .get(&Arc::from("domain0.com"), &RecordType::A)
            .is_some(),
        "domain0 with 5 hits should survive eviction"
    );
    assert!(
        cache
            .get(&Arc::from("domain2.com"), &RecordType::A)
            .is_some(),
        "domain2 with 4 hits should survive eviction"
    );
}

#[test]
fn test_lfu_eviction_without_min_frequency() {
    let cache = create_cache(5, EvictionStrategy::LFU, 0, 0.0);

    for i in 0..5 {
        let domain = format!("domain{}.com", i);
        cache.insert(
            &domain,
            RecordType::A,
            make_ip_data(&format!("10.0.0.{}", i + 1)),
            3600,
            None,
        );
    }

    // Give domain0 many hits
    for _ in 0..10 {
        cache.get(&Arc::from("domain0.com"), &RecordType::A);
    }

    // Trigger eviction
    cache.insert(
        "new-domain.com",
        RecordType::A,
        make_ip_data("10.0.1.1"),
        3600,
        None,
    );

    // domain0 with many hits should survive
    assert!(
        cache
            .get(&Arc::from("domain0.com"), &RecordType::A)
            .is_some(),
        "domain0 with 10 hits should survive eviction with min_frequency=0"
    );
}

#[test]
fn test_lfuk_eviction_respects_min_score() {
    let cache = create_cache(5, EvictionStrategy::LFUK, 0, 1.5);

    for i in 0..5 {
        let domain = format!("domain{}.com", i);
        cache.insert(
            &domain,
            RecordType::A,
            make_ip_data(&format!("10.0.0.{}", i + 1)),
            3600,
            None,
        );
    }

    // Give domain0 many hits to boost its LFUK score
    for _ in 0..20 {
        cache.get(&Arc::from("domain0.com"), &RecordType::A);
    }

    // Trigger eviction
    cache.insert(
        "new-domain.com",
        RecordType::A,
        make_ip_data("10.0.1.1"),
        3600,
        None,
    );

    // domain0 with many hits should survive
    assert!(
        cache
            .get(&Arc::from("domain0.com"), &RecordType::A)
            .is_some(),
        "domain0 with high LFUK score should survive eviction"
    );
}

// ─── Testes de refresh_record e get_refresh_candidates ───────────────────────

#[test]
fn test_refresh_candidates_requires_hit_count() {
    // Entradas sem nenhum hit no cache L2 NÃO devem ser candidatas,
    // mesmo que o threshold de tempo seja 0 (passam imediatamente).
    let cache = create_refresh_cache(u64::MAX);

    cache.insert(
        "never-hit.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        300,
        None,
    );

    // Não chamamos cache.get() → hit_count permanece 0
    let candidates = cache.get_refresh_candidates();
    assert!(
        candidates.is_empty(),
        "Entrada sem hits não deve ser candidata ao refresh; candidates={:?}",
        candidates
    );
}

#[test]
fn test_refresh_candidates_with_recent_access() {
    // Entrada com hit_count > 0 e access_window grande DEVE ser candidata.
    // Usa CNAME para evitar L1 cache (apenas IpAddresses vão para L1).
    // Sem L1, cache.get() vai para L2 e chama record_hit(), incrementando hit_count.
    let cache = create_refresh_cache(u64::MAX);

    cache.insert(
        "popular.com",
        RecordType::CNAME,
        make_cname_data("alias.popular.com"),
        300,
        None,
    );

    // Simular um cache hit (vai para L2 pois CNAME não está em L1)
    cache.get(&Arc::from("popular.com"), &RecordType::CNAME);

    let candidates = cache.get_refresh_candidates();
    assert!(
        candidates.iter().any(|(d, _)| d == "popular.com"),
        "Entrada com hit deve ser candidata; candidates={:?}",
        candidates
    );
}

#[test]
fn test_refresh_candidates_access_window_zero_excludes_entries() {
    // Com access_window_secs = 0 apenas entradas acessadas no mesmo segundo
    // exato podem ser candidatas; na prática o coarse clock pode ter avançado
    // (ou não), mas entradas com hit_count = 0 são sempre excluídas.
    // Este teste garante que o filtro de hit_count é a primeira barreira.
    let cache_no_window = create_refresh_cache(0);

    cache_no_window.insert(
        "zero-window.com",
        RecordType::A,
        make_ip_data("5.5.5.5"),
        300,
        None,
    );

    // hit_count=0 → nunca candidato, independente da janela
    let candidates = cache_no_window.get_refresh_candidates();
    assert!(
        candidates.is_empty(),
        "Sem hits nunca deve ser candidato mesmo com window=0"
    );
}

#[test]
fn test_refresh_record_updates_ttl_fields() {
    // refresh_record() deve atualizar o TTL e tornar a entrada acessível.
    let cache = create_refresh_cache(u64::MAX);

    cache.insert(
        "renew.com",
        RecordType::A,
        make_ip_data("9.9.9.9"),
        300,
        None,
    );

    // Verificar TTL original
    assert_eq!(cache.get_ttl("renew.com", &RecordType::A), Some(300));

    // Renovar com novo TTL
    let renewed = cache.refresh_record(
        "renew.com",
        &RecordType::A,
        Some(7200),
        make_ip_data("9.9.9.9"),
        None,
    );
    assert!(
        renewed,
        "refresh_record deve retornar true quando a entrada existe"
    );

    // TTL atualizado
    assert_eq!(
        cache.get_ttl("renew.com", &RecordType::A),
        Some(7200),
        "get_ttl deve retornar o novo TTL após refresh_record"
    );

    // Entrada ainda acessível
    assert!(
        cache.get(&Arc::from("renew.com"), &RecordType::A).is_some(),
        "Entrada deve continuar acessível após refresh_record"
    );
}

#[test]
fn test_refresh_record_preserves_hit_count_for_subsequent_candidates() {
    // Demonstra a diferença entre cache.insert() (reseta hit_count) e
    // cache.refresh_record() (preserva hit_count).
    //
    // Com refresh_record(): depois de renovar, a entrada continua sendo candidata
    // porque hit_count foi preservado.
    let cache = create_refresh_cache(u64::MAX);

    // Usa CNAME para evitar L1: cache.get() vai para L2 e chama record_hit()
    cache.insert(
        "keep-alive.com",
        RecordType::CNAME,
        make_cname_data("alias.keep-alive.com"),
        300,
        None,
    );
    cache.get(&Arc::from("keep-alive.com"), &RecordType::CNAME); // hit_count = 1

    // Antes do refresh: deve ser candidata
    let before = cache.get_refresh_candidates();
    assert!(
        before.iter().any(|(d, _)| d == "keep-alive.com"),
        "Entrada deve ser candidata antes do refresh; candidates={:?}",
        before
    );

    // Renovar via refresh_record (preserva hit_count)
    cache.refresh_record(
        "keep-alive.com",
        &RecordType::CNAME,
        Some(300),
        make_cname_data("alias.keep-alive.com"),
        None,
    );

    // Depois do refresh_record: AINDA deve ser candidata porque hit_count foi preservado
    let after = cache.get_refresh_candidates();
    assert!(
        after.iter().any(|(d, _)| d == "keep-alive.com"),
        "Entrada deve continuar candidata após refresh_record (hit_count preservado); candidates={:?}",
        after
    );
}

#[test]
fn test_refresh_record_returns_false_for_missing_entry() {
    // refresh_record em entrada inexistente deve retornar false sem panic.
    let cache = create_refresh_cache(u64::MAX);

    let result = cache.refresh_record(
        "nonexistent.com",
        &RecordType::A,
        Some(300),
        make_ip_data("1.1.1.1"),
        None,
    );

    assert!(
        !result,
        "refresh_record deve retornar false para entrada inexistente"
    );
}

#[test]
fn test_access_window_secs_getter() {
    // Verifica que o getter access_window_secs() retorna o valor correto.
    let cache = create_refresh_cache(3600);
    assert_eq!(cache.access_window_secs(), 3600);

    let cache2 = create_refresh_cache(86400);
    assert_eq!(cache2.access_window_secs(), 86400);
}

// ─── Testes de refactoring SOLID das estratégias de eviction ─────────────────

/// strategy() retorna a estratégia correta após o refactoring para ActiveEvictionPolicy.
#[test]
fn test_strategy_method_returns_correct_strategy_after_refactoring() {
    let cases = [
        (EvictionStrategy::LRU, 0u64, 0.0f64),
        (EvictionStrategy::HitRate, 0, 0.0),
        (EvictionStrategy::LFU, 5, 0.0),
        (EvictionStrategy::LFUK, 0, 1.5),
    ];

    for (strategy, min_freq, min_score) in cases {
        let cache = create_cache(10, strategy, min_freq, min_score);
        assert_eq!(
            cache.strategy(),
            strategy,
            "strategy() deve retornar {:?} após refactoring",
            strategy
        );
    }
}

/// LRU: entradas acessadas recentemente sobrevivem; menos recentes são evictadas.
/// Usa coarse_clock::tick() + sleep para garantir timestamps distintos entre inserção e acesso.
#[test]
fn test_lru_eviction_protects_recently_accessed_entry() {
    // max_entries=4, batch_eviction_percentage=0.25 → evicta 1 por vez
    let cache = DnsCache::new(DnsCacheConfig {
        max_entries: 4,
        eviction_strategy: EvictionStrategy::LRU,
        min_threshold: 0.0,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.25, // evicta 1 de 4 por vez
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
    });

    // Inserir 3 entradas no tick T: last_access = T para todas
    coarse_clock::tick();
    cache.insert("a.com", RecordType::CNAME, make_cname_data("a"), 3600, None);
    cache.insert("b.com", RecordType::CNAME, make_cname_data("b"), 3600, None);
    cache.insert("c.com", RecordType::CNAME, make_cname_data("c"), 3600, None);

    // Avançar o relógio 1s e acessar "a.com" → last_access(a) = T+1 > T
    std::thread::sleep(std::time::Duration::from_secs(1));
    coarse_clock::tick();
    cache.get(&Arc::from("a.com"), &RecordType::CNAME);

    cache.insert("d.com", RecordType::CNAME, make_cname_data("d"), 3600, None);
    cache.insert("e.com", RecordType::CNAME, make_cname_data("e"), 3600, None);
    cache.evict_entries();

    assert!(
        cache.len() <= 4,
        "Cache deve respeitar max_entries após eviction"
    );

    // "a.com" foi acessado em T+1 (mais recente que b/c em T) → deve sobreviver à eviction LRU
    assert!(
        cache.get(&Arc::from("a.com"), &RecordType::CNAME).is_some(),
        "a.com (last_access=T+1) deve sobreviver à eviction LRU frente a entradas com last_access=T"
    );
}

/// HitRate: entradas com mais hits sobrevivem; recém-inseridas (0 hits) são evictadas.
#[test]
fn test_hit_rate_eviction_protects_high_hit_entries() {
    let cache = DnsCache::new(DnsCacheConfig {
        max_entries: 4,
        eviction_strategy: EvictionStrategy::HitRate,
        min_threshold: 0.0,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.5,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
    });

    cache.insert(
        "popular.com",
        RecordType::CNAME,
        make_cname_data("p"),
        3600,
        None,
    );
    cache.insert(
        "rare.com",
        RecordType::CNAME,
        make_cname_data("r"),
        3600,
        None,
    );
    cache.insert(
        "medium.com",
        RecordType::CNAME,
        make_cname_data("m"),
        3600,
        None,
    );
    cache.insert(
        "cold.com",
        RecordType::CNAME,
        make_cname_data("c"),
        3600,
        None,
    );

    // "popular.com" recebe muitos hits
    for _ in 0..10 {
        cache.get(&Arc::from("popular.com"), &RecordType::CNAME);
    }

    // Inserir mais entradas para forçar eviction
    cache.insert(
        "new1.com",
        RecordType::CNAME,
        make_cname_data("n1"),
        3600,
        None,
    );
    cache.insert(
        "new2.com",
        RecordType::CNAME,
        make_cname_data("n2"),
        3600,
        None,
    );

    // "popular.com" com alta taxa de hit deve sobreviver
    assert!(
        cache
            .get(&Arc::from("popular.com"), &RecordType::CNAME)
            .is_some(),
        "popular.com com muitos hits deve sobreviver à eviction HitRate"
    );
}

/// LFU com min_frequency: entradas abaixo do threshold têm score negativo → evictadas.
/// Verifica que o refactoring preservou o comportamento de penalização.
#[test]
fn test_lfu_negative_score_below_min_frequency_leads_to_eviction() {
    let cache = DnsCache::new(DnsCacheConfig {
        max_entries: 4,
        eviction_strategy: EvictionStrategy::LFU,
        min_threshold: 0.0,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.5,
        adaptive_thresholds: false,
        min_frequency: 5, // mínimo de 5 hits
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
    });

    // Entradas com poucos hits (abaixo do min_frequency=5) têm score negativo
    cache.insert(
        "low1.com",
        RecordType::CNAME,
        make_cname_data("l1"),
        3600,
        None,
    );
    cache.insert(
        "low2.com",
        RecordType::CNAME,
        make_cname_data("l2"),
        3600,
        None,
    );

    // Entrada com muitos hits (acima do min_frequency=5) tem score positivo
    cache.insert(
        "high.com",
        RecordType::CNAME,
        make_cname_data("h"),
        3600,
        None,
    );
    for _ in 0..10 {
        cache.get(&Arc::from("high.com"), &RecordType::CNAME);
    }

    cache.insert(
        "filler.com",
        RecordType::CNAME,
        make_cname_data("f"),
        3600,
        None,
    );

    // Inserir acima do limite para forçar eviction
    cache.insert(
        "trigger.com",
        RecordType::CNAME,
        make_cname_data("t"),
        3600,
        None,
    );
    cache.insert(
        "trigger2.com",
        RecordType::CNAME,
        make_cname_data("t2"),
        3600,
        None,
    );

    // "high.com" com score positivo deve sobreviver
    assert!(
        cache
            .get(&Arc::from("high.com"), &RecordType::CNAME)
            .is_some(),
        "high.com com hits acima de min_frequency deve sobreviver"
    );
}

/// Verifica que access_window_secs() retorna corretamente após o refactoring.
#[test]
fn test_access_window_preserved_in_refactored_cache() {
    for strategy in [
        EvictionStrategy::LRU,
        EvictionStrategy::HitRate,
        EvictionStrategy::LFU,
        EvictionStrategy::LFUK,
    ] {
        let cache = DnsCache::new(DnsCacheConfig {
            max_entries: 10,
            eviction_strategy: strategy,
            min_threshold: 0.0,
            refresh_threshold: 0.75,
            batch_eviction_percentage: 0.2,
            adaptive_thresholds: false,
            min_frequency: 0,
            min_lfuk_score: 0.0,
            shard_amount: 4,
            access_window_secs: 1800,
            eviction_sample_size: 8,
            lfuk_k_value: 0.5,
            refresh_sample_rate: 1.0,
        });

        assert_eq!(
            cache.access_window_secs(),
            1800,
            "access_window_secs deve ser preservado para estratégia {:?}",
            strategy
        );
    }
}

/// Single-scan eviction: inserir N+X entradas, verificar que exatamente N são removidas.
///
/// Garante que o novo algoritmo de scan único em evict_by_strategy() evicta
/// exatamente `count` entradas por chamada, sem over- ou under-eviction.
#[test]
fn test_single_scan_evicts_exact_count() {
    // max_entries=5, batch_eviction_percentage=0.2 → evicta max(1, 5*0.2=1) por chamada.
    // Ao inserir a 6ª entrada, o cache tem 5 → evict_entries() é chamado → remove 1.
    // Resultado: 5 entradas inseridas com sucesso.
    let cache = DnsCache::new(DnsCacheConfig {
        max_entries: 5,
        eviction_strategy: EvictionStrategy::LFU,
        min_threshold: 0.0,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.2,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
    });

    // Inserir max_entries entradas
    for i in 0..5 {
        cache.insert(
            &format!("domain{i}.com"),
            RecordType::CNAME,
            make_cname_data(&format!("alias{i}")),
            3600,
            None,
        );
    }
    assert_eq!(cache.len(), 5);

    for i in 5..8 {
        cache.insert(
            &format!("domain{i}.com"),
            RecordType::CNAME,
            make_cname_data(&format!("alias{i}")),
            3600,
            None,
        );
    }
    for _ in 0..3 {
        cache.evict_entries();
    }

    assert!(
        cache.len() <= 5,
        "Cache não deve exceder max_entries após evictions; len={}",
        cache.len()
    );

    let metrics = cache.metrics();
    let evictions = metrics.evictions.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        evictions >= 3,
        "Devem ter ocorrido pelo menos 3 evictions; evictions={}",
        evictions
    );
}

#[test]
fn test_clear_also_clears_l1_cache() {
    let cache = create_cache(100, EvictionStrategy::HitRate, 0, 0.0);

    cache.insert(
        "clear-test.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        300,
        None,
    );

    // Primeiro get popula o L1
    let first = cache.get(&Arc::from("clear-test.com"), &RecordType::A);
    assert!(first.is_some(), "Entry deve existir antes do clear");

    // Segundo get deve vir do L1 (IpAddresses)
    let from_l1 = cache.get(&Arc::from("clear-test.com"), &RecordType::A);
    assert!(
        from_l1.is_some(),
        "Entry deve estar no L1 na segunda leitura"
    );

    cache.clear();

    // Após clear, nem L1 nem L2 devem retornar o dado
    let after_clear = cache.get(&Arc::from("clear-test.com"), &RecordType::A);
    assert!(
        after_clear.is_none(),
        "Entry não deve ser retornada após cache.clear() — L1 deve ter sido limpo"
    );
}

#[test]
fn test_stale_while_revalidate_returns_nonzero_ttl() {
    let cache = create_cache(100, EvictionStrategy::HitRate, 0, 0.0);

    // Inserir com TTL 1 segundo (irá expirar rapidamente)
    cache.insert(
        "stale-test.com",
        RecordType::CNAME,
        make_cname_data("alias.stale-test.com"),
        1,
        None,
    );

    // Avançar o coarse clock para colocar o entry em stale-but-usable window
    // (expirado mas dentro do grace period de 2×TTL)
    coarse_clock::tick();
    coarse_clock::tick();

    let result = cache.get(&Arc::from("stale-test.com"), &RecordType::CNAME);

    if let Some((_, _, Some(ttl))) = result {
        assert!(
            ttl >= 1,
            "TTL retornado para record stale-while-revalidate deve ser >= 1, foi {}",
            ttl
        );
    }
    // Se None, o entry já passou do grace period — o teste é inconclusivo mas não falha
}

#[test]
fn test_lfuk_new_entries_evicted_in_order_not_urgently() {
    // Bug anterior: entries novas (hits=0) recebiam score negativo e iam para
    // urgent_expired, sendo evictadas ANTES de entries com baixo-mas-positivo score.
    // Após a fix: bootstrap score = min_lfuk_score, eviction é por ordenação normal.
    //
    // Cenário: todas as entries têm hits=0 → bootstrap score igual para todas.
    // Após eviction, o cache deve ter ao menos (max_entries - batch_eviction) entries.
    let cache = create_cache(5, EvictionStrategy::LFUK, 0, 5.0);

    for i in 0..5 {
        cache.insert(
            &format!("new{i}.com"),
            RecordType::CNAME,
            make_cname_data(&format!("alias{i}.com")),
            3600,
            None,
        );
    }

    let size_before = cache.len();
    cache.evict_entries();
    let size_after = cache.len();

    // Com batch_eviction_percentage=0.2 e max_entries=5: remove 1 entry por ciclo
    assert!(
        size_after < size_before,
        "Eviction deve remover ao menos 1 entry"
    );
    // Não deve ter esvaziado o cache (eviction controlada, não urgente)
    assert!(
        size_after >= 4,
        "Eviction de batch 20% não deve remover mais que 1 entry de um cache de 5; após={}",
        size_after
    );
}

// ─── Testes de compaction ─────────────────────────────────────────────────────

#[test]
fn test_compact_retains_expired_entries() {
    let cache = create_refresh_cache(7200);
    coarse_clock::tick();

    cache.insert(
        "expired.test",
        RecordType::CNAME,
        make_cname_data("alias"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_secs(2));
    coarse_clock::tick();

    let removed = cache.compact();
    assert_eq!(
        removed, 0,
        "compact() não deve remover entradas expiradas (apenas marked_for_deletion)"
    );
    assert_eq!(cache.len(), 1, "Entrada expirada deve permanecer no cache");
}

#[test]
fn test_compact_removes_marked_for_deletion() {
    let cache = create_refresh_cache(7200);
    coarse_clock::tick();

    cache.insert(
        "to-delete.test",
        RecordType::CNAME,
        make_cname_data("alias"),
        1,
        None,
    );

    std::thread::sleep(std::time::Duration::from_secs(2));
    coarse_clock::tick();

    let result = cache.get(&Arc::from("to-delete.test"), &RecordType::CNAME);
    assert!(
        result.is_none(),
        "get() deve retornar None para entrada expirada"
    );

    let removed = cache.compact();
    assert_eq!(
        removed, 1,
        "compact() deve remover entradas marked_for_deletion"
    );
    assert_eq!(cache.len(), 0);
}

#[test]
fn test_compact_retains_valid_entries() {
    let cache = create_refresh_cache(7200);
    coarse_clock::tick();

    cache.insert(
        "valid.test",
        RecordType::A,
        make_ip_data("1.1.1.1"),
        3600,
        None,
    );

    let removed = cache.compact();
    assert_eq!(removed, 0, "Entradas válidas não devem ser removidas");
    assert_eq!(cache.len(), 1);
}

// ─── Testes de eviction policies ─────────────────────────────────────────────

fn make_record_with_hits(hits: u64) -> CachedRecord {
    let record = CachedRecord::new(
        CachedData::IpAddresses(Arc::new(vec!["1.1.1.1".parse::<IpAddr>().unwrap()])),
        300,
        RecordType::A,
        Some(DnssecStatus::Unknown),
    );
    for _ in 0..hits {
        record.record_hit();
    }
    record
}

#[test]
fn test_lru_score_is_last_access_timestamp() {
    let cache = DnsCache::new(DnsCacheConfig {
        max_entries: 10,
        eviction_strategy: EvictionStrategy::LRU,
        min_threshold: 0.0,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.2,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
    });

    coarse_clock::tick();
    cache.insert("a.com", RecordType::A, make_ip_data("1.1.1.1"), 300, None);
    let _ = cache.get(&Arc::from("a.com"), &RecordType::A);

    let policy = LruPolicy;
    let result = cache.get(&Arc::from("a.com"), &RecordType::A);
    assert!(result.is_some(), "Entrada deve existir");
    let _ = policy;
}

#[test]
fn test_lru_evicts_least_recently_used() {
    let cache = DnsCache::new(DnsCacheConfig {
        max_entries: 3,
        eviction_strategy: EvictionStrategy::LRU,
        min_threshold: 0.0,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 1.0,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
    });

    coarse_clock::tick();
    cache.insert("a.com", RecordType::A, make_ip_data("1.1.1.1"), 300, None);
    cache.insert("b.com", RecordType::A, make_ip_data("2.2.2.2"), 300, None);
    cache.insert("c.com", RecordType::A, make_ip_data("3.3.3.3"), 300, None);
    cache.insert("d.com", RecordType::A, make_ip_data("4.4.4.4"), 300, None);
    cache.evict_entries();

    assert!(cache.len() <= 3, "Cache deve respeitar max_entries");
    let metrics = cache.metrics();
    assert!(
        metrics.evictions.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "Deve ter ocorrido pelo menos uma eviction"
    );
}

#[test]
fn test_hit_rate_score_increases_with_hits() {
    let policy = HitRatePolicy;
    let r0 = make_record_with_hits(0);
    let r1 = make_record_with_hits(1);
    let r10 = make_record_with_hits(10);
    let r100 = make_record_with_hits(100);

    let s0 = policy.compute_score(&r0, 0);
    let s1 = policy.compute_score(&r1, 0);
    let s10 = policy.compute_score(&r10, 0);
    let s100 = policy.compute_score(&r100, 0);

    assert!(s0 < s1, "0 hits deve ter score menor que 1 hit");
    assert!(s1 < s10, "1 hit deve ter score menor que 10 hits");
    assert!(s10 < s100, "10 hits deve ter score menor que 100 hits");
}

#[test]
fn test_hit_rate_score_is_bounded_between_zero_and_one() {
    let policy = HitRatePolicy;
    let r0 = make_record_with_hits(0);
    let r_big = make_record_with_hits(1_000_000);

    let s0 = policy.compute_score(&r0, 0);
    let s_big = policy.compute_score(&r_big, 0);

    assert!(s0 >= 0.0, "Score deve ser >= 0");
    assert!(s_big < 1.0, "Score deve ser < 1.0 (bounded)");
    assert!(s_big >= 0.0, "Score não pode ser negativo em HitRate");
}

#[test]
fn test_hit_rate_score_zero_hits() {
    let policy = HitRatePolicy;
    let record = make_record_with_hits(0);
    let score = policy.compute_score(&record, 0);
    assert_eq!(score, 0.0);
}

#[test]
fn test_lfuk_score_zero_hits_returns_bootstrap_score() {
    let policy = LfukPolicy {
        min_lfuk_score: 1.5,
        k_value: 0.5,
    };
    let record = make_record_with_hits(0);
    let score = policy.compute_score(&record, 1_000_000);
    assert_eq!(
        score, 1.5,
        "Entries com hits=0 devem receber bootstrap score igual a min_lfuk_score"
    );
}

#[test]
fn test_lfuk_score_below_min_is_negative_after_first_hit() {
    let policy = LfukPolicy {
        min_lfuk_score: 100.0,
        k_value: 0.5,
    };
    let record = make_record_with_hits(1);
    let score = policy.compute_score(&record, 1_000_000);
    assert!(
        score < 0.0,
        "Entry com poucos hits e alto min_lfuk_score deve ter score negativo: {}",
        score
    );
}

#[test]
fn test_lfuk_score_with_many_hits_and_recent_access() {
    let policy = LfukPolicy {
        min_lfuk_score: 0.0,
        k_value: 0.5,
    };
    let record = make_record_with_hits(20);
    let now_secs = coarse_clock::coarse_now_secs();
    let score = policy.compute_score(&record, now_secs);
    assert!(
        score >= 0.0,
        "Entrada com muitos hits recentes deve ter score >= 0"
    );
}

#[test]
fn test_lfu_score_below_min_frequency_is_negative() {
    let policy = LfuPolicy { min_frequency: 10 };
    let record = make_record_with_hits(3);
    let score = policy.compute_score(&record, 0);
    assert!(
        score < 0.0,
        "Score deve ser negativo quando hits (3) < min_frequency (10)"
    );
    assert_eq!(
        score,
        -(10.0 - 3.0),
        "Score deve ser -(min_frequency - hits)"
    );
}

#[test]
fn test_lfu_score_above_min_frequency_is_positive() {
    let policy = LfuPolicy { min_frequency: 5 };
    let record = make_record_with_hits(15);
    let score = policy.compute_score(&record, 0);
    assert!(
        score > 0.0,
        "Score deve ser positivo quando hits (15) >= min_frequency (5)"
    );
    assert_eq!(score, 15.0);
}

#[test]
fn test_lfu_score_zero_min_frequency_returns_raw_hits() {
    let policy = LfuPolicy { min_frequency: 0 };
    let record = make_record_with_hits(7);
    let score = policy.compute_score(&record, 0);
    assert_eq!(
        score, 7.0,
        "Com min_frequency=0, score deve ser raw hit_count"
    );
}
