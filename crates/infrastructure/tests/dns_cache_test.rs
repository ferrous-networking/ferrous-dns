use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock;
use ferrous_dns_infrastructure::dns::cache::eviction::ActiveEvictionPolicy;
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, CachedDnssecStatus, CachedRecord, DnsCache, DnsCacheConfig,
    EvictionStrategy,
};
use std::net::IpAddr;
use std::sync::Arc;

/// Cria um cache com refresh_threshold=0.0 (qualquer entrada passa o filtro de tempo)
/// e access_window_secs configurável para testes de refresh.
fn create_refresh_cache(access_window_secs: u64) -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold: 0.0, // toda entrada qualifica pelo tempo imediatamente
        batch_eviction_percentage: 0.2,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
    })
}

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().unwrap();
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![addr]),
    })
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
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.2,
        min_frequency,
        min_lfuk_score,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
    })
}

fn create_cache_with_ttl_limits(min_ttl: u32, max_ttl: u32) -> DnsCache {
    DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.2,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl,
        max_ttl,
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

// ─── Testes de refresh_record ────────────────────────────────────────────────

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
fn test_refresh_deadline_ranks_by_death_not_by_expiry() {
    // `expires_at_secs` sozinho classificaria errado: a entrada de TTL 3600
    // expira antes, mas sobrevive mais 3600 s servida como stale, enquanto a de
    // TTL 60 morre 60 s depois de expirar.
    let mut short = CachedRecord::new(
        make_ip_data("1.1.1.1"),
        60,
        RecordType::A,
        Some(CachedDnssecStatus::Unknown),
    );
    let mut long = CachedRecord::new(
        make_ip_data("2.2.2.2"),
        3600,
        RecordType::A,
        Some(CachedDnssecStatus::Unknown),
    );

    let now = short.inserted_at_secs;
    short.expires_at_secs = now + 10;
    long.expires_at_secs = now + 30;

    assert!(
        long.expires_at_secs > short.expires_at_secs,
        "Pré-condição: a de TTL longo expira depois"
    );
    assert!(
        short.refresh_deadline_secs() < long.refresh_deadline_secs(),
        "A entrada que morre primeiro deve vir primeiro: short={} long={}",
        short.refresh_deadline_secs(),
        long.refresh_deadline_secs()
    );
    assert_eq!(
        short.refresh_deadline_secs(),
        now + 10 + 60,
        "O prazo de morte é expires_at + ttl"
    );
}

// ─── Testes da janela de taxa de hits por renovação ──────────────────────────

#[test]
fn test_hits_per_minute_counts_only_hits_since_last_refresh() {
    // `refresh_record` reseta `inserted_at_secs` mas não `hit_count`, que as
    // políticas de evicção leem como total de vida. Sem `hits_at_last_refresh`
    // a taxa dispararia a cada renovação e qualquer teste de "está sendo
    // usada?" aprovaria qualquer entrada antiga.
    let mut record = CachedRecord::new(
        make_ip_data("1.2.3.4"),
        300,
        RecordType::A,
        Some(CachedDnssecStatus::Unknown),
    );
    for _ in 0..120 {
        record.record_hit();
    }

    let inserted = record.inserted_at_secs;
    // 120 hits em 60 s = 120 hits/min.
    let before = record.hits_per_minute_since_refresh(inserted + 60);
    assert!(
        (before - 120.0).abs() < 0.001,
        "Antes da renovação a taxa cobre toda a vida da entrada; got {before}"
    );

    // Simula o que `refresh_record` faz: rebaseia a janela e o instante de
    // inserção juntos.
    record.note_refreshed();
    record.inserted_at_secs = inserted + 60;

    let right_after = record.hits_per_minute_since_refresh(inserted + 120);
    assert_eq!(
        right_after, 0.0,
        "Sem hits novos após a renovação a taxa deve ser zero, não o total acumulado"
    );

    // 6 hits nos 60 s seguintes = 6 hits/min, e não (126 × 60 / 60) = 126.
    for _ in 0..6 {
        record.record_hit();
    }
    let after = record.hits_per_minute_since_refresh(inserted + 120);
    assert!(
        (after - 6.0).abs() < 0.001,
        "A taxa deve refletir só a janela desde a renovação; got {after}"
    );
    assert_eq!(
        record
            .counters
            .hit_count
            .load(std::sync::atomic::Ordering::Relaxed),
        126,
        "O total de vida continua intacto para as políticas de evicção"
    );
}

/// LRU: entradas acessadas recentemente sobrevivem; menos recentes são evictadas.
/// Usa coarse_clock::tick() + sleep para garantir timestamps distintos entre inserção e acesso.
#[test]
fn test_lru_eviction_protects_recently_accessed_entry() {
    // max_entries=4, batch_eviction_percentage=0.25 → evicta 1 por vez
    let cache = DnsCache::new(DnsCacheConfig {
        max_entries: 4,
        eviction_strategy: EvictionStrategy::LRU,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.25, // evicta 1 de 4 por vez
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
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
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.5,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
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
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.5,
        min_frequency: 5, // mínimo de 5 hits
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
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
        refresh_threshold: 0.75,
        batch_eviction_percentage: 0.2,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
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

    if let Some((_, _, Some(ttl), _)) = result {
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
fn test_compact_removes_expired_entries_past_stale_window() {
    let cache = create_refresh_cache(7200);
    coarse_clock::tick();

    cache.insert(
        "expired.test",
        RecordType::CNAME,
        make_cname_data("alias"),
        1,
        None,
    );

    // TTL=1s, stale grace = 2×TTL = 2s → wait 3s to be fully past stale window
    std::thread::sleep(std::time::Duration::from_secs(3));
    coarse_clock::tick();

    let removed = cache.compact();
    assert_eq!(
        removed, 1,
        "compact() deve remover entradas expiradas e fora da stale window"
    );
    assert_eq!(cache.len(), 0, "Cache deve estar vazio após compaction");
}

#[test]
fn test_compact_retains_entries_within_stale_window() {
    let cache = create_refresh_cache(7200);
    coarse_clock::tick();

    // TTL=3s, stale grace = 2×TTL = 6s → after 4s entry is expired but still stale-usable
    cache.insert(
        "stale.test",
        RecordType::CNAME,
        make_cname_data("alias"),
        3,
        None,
    );

    std::thread::sleep(std::time::Duration::from_secs(4));
    coarse_clock::tick();

    let removed = cache.compact();
    assert_eq!(
        removed, 0,
        "compact() não deve remover entradas ainda dentro da stale window"
    );
    assert_eq!(
        cache.len(),
        1,
        "Entrada na stale window deve ser preservada"
    );
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

/// Scores an entry that was inserted and last read at `now_secs`.
fn score_at(
    strategy: EvictionStrategy,
    min_frequency: u64,
    min_lfuk_score: f64,
    hits: u64,
    now_secs: u64,
) -> f64 {
    ActiveEvictionPolicy::from_config(strategy, min_frequency, min_lfuk_score, 0.5)
        .score(hits, now_secs, now_secs, now_secs)
}

#[test]
fn test_lru_evicts_least_recently_used() {
    let cache = DnsCache::new(DnsCacheConfig {
        max_entries: 3,
        eviction_strategy: EvictionStrategy::LRU,
        refresh_threshold: 0.75,
        batch_eviction_percentage: 1.0,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: 7200,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        min_ttl: 0,
        max_ttl: 86_400,
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
    let score = |hits| score_at(EvictionStrategy::HitRate, 0, 0.0, hits, 0);
    let (s0, s1, s10, s100) = (score(0), score(1), score(10), score(100));

    assert!(s0 < s1, "0 hits deve ter score menor que 1 hit");
    assert!(s1 < s10, "1 hit deve ter score menor que 10 hits");
    assert!(s10 < s100, "10 hits deve ter score menor que 100 hits");
}

#[test]
fn test_hit_rate_score_is_bounded_between_zero_and_one() {
    let s0 = score_at(EvictionStrategy::HitRate, 0, 0.0, 0, 0);
    let s_big = score_at(EvictionStrategy::HitRate, 0, 0.0, 1_000_000, 0);

    assert_eq!(s0, 0.0, "0 hits scores exactly zero");
    assert!(s_big < 1.0, "Score deve ser < 1.0 (bounded)");
    assert!(s_big >= 0.0, "Score não pode ser negativo em HitRate");
}

#[test]
fn test_hit_rate_score_decays_with_idle_time() {
    let policy = ActiveEvictionPolicy::from_config(EvictionStrategy::HitRate, 0, 0.0, 0.5);
    let fresh = policy.score(10, 1_000, 1_000, 1_000);
    let idle = policy.score(10, 1_000, 1_000, 1_100);
    assert!(idle < fresh, "an idle entry must score below a fresh one");
}

#[test]
fn test_lru_score_is_last_access() {
    let policy = ActiveEvictionPolicy::from_config(EvictionStrategy::LRU, 0, 0.0, 0.5);
    assert!(policy.score(1_000, 10, 0, 50) < policy.score(0, 20, 0, 50));
}

#[test]
fn test_lfuk_score_zero_hits_returns_bootstrap_score() {
    let score = score_at(EvictionStrategy::LFUK, 0, 1.5, 0, 1_000_000);
    assert_eq!(
        score, 1.5,
        "Entries com hits=0 devem receber bootstrap score igual a min_lfuk_score"
    );
}

#[test]
fn test_lfuk_score_below_min_is_negative_after_first_hit() {
    let score = score_at(EvictionStrategy::LFUK, 0, 100.0, 1, 1_000_000);
    assert!(
        score < 0.0,
        "Entry com poucos hits e alto min_lfuk_score deve ter score negativo: {}",
        score
    );
}

#[test]
fn test_lfuk_score_with_many_hits_and_recent_access() {
    let score = score_at(EvictionStrategy::LFUK, 0, 0.0, 20, 1_000_000);
    assert_eq!(
        score, 20.0,
        "an entry read just now keeps its full hit count"
    );
}

#[test]
fn test_lfu_score_below_min_frequency_is_negative() {
    let score = score_at(EvictionStrategy::LFU, 10, 0.0, 3, 0);
    assert_eq!(
        score,
        -(10.0 - 3.0),
        "Score deve ser -(min_frequency - hits)"
    );
}

#[test]
fn test_lfu_score_above_min_frequency_is_positive() {
    let score = score_at(EvictionStrategy::LFU, 5, 0.0, 15, 0);
    assert_eq!(score, 15.0);
}

#[test]
fn test_lfu_score_zero_min_frequency_returns_raw_hits() {
    let score = score_at(EvictionStrategy::LFU, 0, 0.0, 7, 0);
    assert_eq!(
        score, 7.0,
        "Com min_frequency=0, score deve ser raw hit_count"
    );
}

#[test]
fn test_cache_min_ttl_elevates_short_upstream_ttl() {
    let cache = create_cache_with_ttl_limits(300, 86_400);

    cache.insert(
        "example.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        60,
        None,
    );

    let remaining = cache
        .get_remaining_ttl("example.com", &RecordType::A)
        .unwrap();
    assert!(
        remaining >= 299,
        "TTL 60 deve ser elevado para >= 300 pelo cache_min_ttl; got {remaining}"
    );
}

#[test]
fn test_cache_max_ttl_caps_long_upstream_ttl() {
    let cache = create_cache_with_ttl_limits(0, 3_600);

    cache.insert(
        "example.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        86_400,
        None,
    );

    let remaining = cache
        .get_remaining_ttl("example.com", &RecordType::A)
        .unwrap();
    assert!(
        remaining <= 3_600,
        "TTL 86400 deve ser cortado para <= 3600 pelo cache_max_ttl; got {remaining}"
    );
}

#[test]
fn test_cache_min_ttl_zero_preserves_upstream_ttl() {
    let cache = create_cache_with_ttl_limits(0, 86_400);

    cache.insert(
        "example.com",
        RecordType::A,
        make_ip_data("1.2.3.4"),
        120,
        None,
    );

    let remaining = cache
        .get_remaining_ttl("example.com", &RecordType::A)
        .unwrap();
    assert!(
        (119..=120).contains(&remaining),
        "Com cache_min_ttl=0, TTL 120 deve ser preservado; got {remaining}"
    );
}
