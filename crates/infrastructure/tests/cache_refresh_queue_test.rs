//! Testes das filas de refresh em background.
//!
//! Antes, `run_refresh_cycle` resolvia cada candidato inline e em sequência: o
//! único freio era a latência do upstream, então um resolver local rápido fazia
//! o ciclo renovar toda a working set elegível de uma vez. Agora o ciclo apenas
//! varre e enfileira, e o worker drena no ritmo configurado — mas só a fila
//! optimistic. Serve-stale tem fila própria, sem pacer: um cliente já recebeu
//! resposta velha e está esperando a boa. As filas são separadas justamente
//! porque uma FIFO única faria o item stale esperar todo o backlog paced.

use async_trait::async_trait;
use ferrous_dns_application::ports::{CacheMaintenancePort, DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, DnsCacheMaintenance, EvictionStrategy,
    RefreshRequest, RefreshSenders,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Conecta as duas filas ao cache e devolve os receivers.
fn wire_queues(
    cache: &DnsCache,
    stale_capacity: usize,
    optimistic_capacity: usize,
) -> (
    mpsc::Receiver<RefreshRequest>,
    mpsc::Receiver<RefreshRequest>,
) {
    let (stale_tx, stale_rx) = mpsc::channel(stale_capacity);
    let (optimistic_tx, optimistic_rx) = mpsc::channel(optimistic_capacity);
    cache.set_refresh_senders(RefreshSenders {
        stale: stale_tx,
        optimistic: optimistic_tx,
    });
    (stale_rx, optimistic_rx)
}

/// Cache com `refresh_threshold = 0.0`: toda entrada viva e dentro da janela de
/// acesso vira candidata, o que torna a contagem de candidatos previsível.
fn create_refresh_cache() -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries: 100,
        eviction_strategy: EvictionStrategy::HitRate,
        min_threshold: 0.0,
        refresh_threshold: 0.0,
        batch_eviction_percentage: 0.2,
        adaptive_thresholds: false,
        min_frequency: 0,
        min_lfuk_score: 0.0,
        shard_amount: 4,
        access_window_secs: u64::MAX,
        eviction_sample_size: 8,
        lfuk_k_value: 0.5,
        refresh_sample_rate: 1.0,
        min_ttl: 0,
        max_ttl: 86_400,
    }))
}

fn make_ip_data(ip: &str) -> CachedData {
    let addr: IpAddr = ip.parse().expect("IP de teste inválido");
    CachedData::IpAddresses(CachedAddresses {
        addresses: Arc::new(vec![addr]),
    })
}

fn insert_entries(cache: &DnsCache, count: usize) {
    for i in 0..count {
        cache.insert(
            &format!("queued-{i}.com"),
            RecordType::A,
            make_ip_data("1.2.3.4"),
            300,
            None,
        );
    }
}

/// Resolver que registra, em ordem, os domínios que lhe foram pedidos.
struct RecordingResolver {
    calls: Arc<Mutex<Vec<String>>>,
    count: Arc<AtomicUsize>,
}

impl RecordingResolver {
    fn new() -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    fn saw(&self, domain: &str) -> bool {
        self.calls
            .lock()
            .expect("mutex de calls envenenado")
            .iter()
            .any(|d| d == domain)
    }
}

#[async_trait]
impl DnsResolver for RecordingResolver {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError> {
        self.calls
            .lock()
            .expect("mutex de calls envenenado")
            .push(query.domain.to_string());
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(DnsResolution::new(
            vec!["9.9.9.9".parse().expect("IP de teste inválido")],
            false,
        ))
    }
}

#[tokio::test]
async fn test_refresh_cycle_enqueues_instead_of_refreshing_inline() {
    // O ciclo não resolve nada: ele entrega os candidatos à fila e retorna.
    let cache = create_refresh_cache();
    let (_stale_rx, mut rx) = wire_queues(&cache, 8, 64);
    insert_entries(&cache, 5);

    let maintenance = DnsCacheMaintenance::new(Arc::clone(&cache), 60);
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");

    assert_eq!(outcome.candidates_found, 5);
    assert_eq!(outcome.enqueued, 5, "todos os candidatos devem ser aceitos");
    assert_eq!(outcome.dropped, 0);

    let mut queued = Vec::new();
    while let Ok((domain, _)) = rx.try_recv() {
        queued.push(domain.to_string());
    }

    assert_eq!(
        queued.len(),
        5,
        "os 5 candidatos devem estar na fila; queued={queued:?}"
    );
}

#[tokio::test]
async fn test_refresh_cycle_overflow_does_not_strand_entries() {
    // Com fila de 2 e 5 candidatos, os 3 excedentes não podem ficar presos no
    // estado "refreshing" — precisam voltar a ser candidatos no próximo ciclo.
    let cache = create_refresh_cache();
    let (_stale_rx, mut rx) = wire_queues(&cache, 8, 2);
    insert_entries(&cache, 5);

    let maintenance = DnsCacheMaintenance::new(Arc::clone(&cache), 60);
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");

    assert_eq!(outcome.candidates_found, 5);
    assert_eq!(outcome.enqueued, 2, "a fila só comporta 2");
    assert_eq!(outcome.dropped, 3, "os outros 3 devem ser recusados");

    // Drena a fila para liberar espaço e simular o worker consumindo.
    let mut drained = Vec::new();
    while let Ok((domain, _)) = rx.try_recv() {
        drained.push(domain.to_string());
    }
    assert_eq!(drained.len(), 2);

    // Os 3 recusados continuam elegíveis: uma nova varredura deve encontrá-los.
    let again = cache.get_refresh_candidates();
    assert_eq!(
        again.len(),
        3,
        "os candidatos recusados devem seguir elegíveis; again={again:?}"
    );
    for (domain, _) in &again {
        assert!(
            !drained.contains(&domain.to_string()),
            "um candidato já enfileirado não pode reaparecer; domain={domain}"
        );
    }
}

#[tokio::test]
async fn test_cycle_without_worker_does_not_strand_entries() {
    // Sem sender configurado nada drenaria a fila, então o ciclo precisa
    // liberar as flags em vez de deixar as entradas marcadas para sempre.
    let cache = create_refresh_cache();
    insert_entries(&cache, 3);

    let maintenance = DnsCacheMaintenance::new(Arc::clone(&cache), 60);
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");

    assert_eq!(outcome.candidates_found, 3);
    assert_eq!(outcome.enqueued, 0);

    let again = cache.get_refresh_candidates();
    assert_eq!(
        again.len(),
        3,
        "sem worker, as entradas devem continuar elegíveis; again={again:?}"
    );
}

#[tokio::test]
async fn test_stale_refresh_bypasses_the_pacer() {
    // Rate de 0.5/s = um tick a cada 2s. O primeiro tick do interval sai
    // imediatamente, então gastamos ele com um item optimistic; depois disso o
    // pacer só liberaria outro 2s adiante. Um item stale enviado na sequência
    // precisa ser resolvido muito antes disso.
    let cache = create_refresh_cache();
    let resolver = Arc::new(RecordingResolver::new());
    let (stale_tx, stale_rx) = mpsc::channel(16);
    let (optimistic_tx, optimistic_rx) = mpsc::channel(16);

    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        stale_rx,
        optimistic_rx,
        0.5,
    );

    optimistic_tx
        .send((Arc::from("warmup.com"), RecordType::A))
        .await
        .expect("envio do warmup falhou");
    tokio::time::sleep(Duration::from_millis(150)).await;

    stale_tx
        .send((Arc::from("urgent.com"), RecordType::A))
        .await
        .expect("envio do stale falhou");
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        resolver.saw("urgent.com"),
        "um refresh stale não pode esperar o pacer; calls={:?}",
        resolver.calls.lock().expect("mutex envenenado")
    );
}

#[tokio::test]
async fn test_stale_refresh_does_not_wait_behind_optimistic_backlog() {
    // Regressão da fila única: com um backlog optimistic grande drenando a
    // 2/s, um item stale enfileirado *depois* dele precisa sair de imediato.
    // Numa FIFO compartilhada o worker ficaria parado no pacer do primeiro
    // optimistic e o stale só seria visto depois de todo o lote — dezenas de
    // segundos. Com filas separadas e `biased`, ele passa na frente.
    let cache = create_refresh_cache();
    let resolver = Arc::new(RecordingResolver::new());
    let (stale_tx, stale_rx) = mpsc::channel(16);
    let (optimistic_tx, optimistic_rx) = mpsc::channel(64);

    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        stale_rx,
        optimistic_rx,
        2.0,
    );

    // 40 itens a 2/s = 20 segundos de backlog.
    for i in 0..40 {
        optimistic_tx
            .send((
                Arc::from(format!("backlog-{i}.com").as_str()),
                RecordType::A,
            ))
            .await
            .expect("envio do backlog falhou");
    }

    // Deixa o worker consumir o tick imediato e travar no pacer.
    tokio::time::sleep(Duration::from_millis(100)).await;

    stale_tx
        .send((Arc::from("urgent.com"), RecordType::A))
        .await
        .expect("envio do stale falhou");
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        resolver.saw("urgent.com"),
        "o stale não pode esperar o backlog paced drenar; calls={:?}",
        resolver.calls.lock().expect("mutex envenenado")
    );
    assert!(
        resolver.count() < 40,
        "o backlog optimistic deve seguir paced; count={}",
        resolver.count()
    );
}

#[tokio::test]
async fn test_optimistic_refresh_is_paced() {
    // Rate de 4/s = 250ms entre itens. Três optimistic não podem sair todos de
    // uma vez, mas todos precisam sair no fim.
    let cache = create_refresh_cache();
    let resolver = Arc::new(RecordingResolver::new());
    let (_stale_tx, stale_rx) = mpsc::channel(16);
    let (tx, optimistic_rx) = mpsc::channel(16);

    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        stale_rx,
        optimistic_rx,
        4.0,
    );

    for i in 0..3 {
        tx.send((Arc::from(format!("paced-{i}.com").as_str()), RecordType::A))
            .await
            .expect("envio falhou");
    }

    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        resolver.count() < 3,
        "o pacer deve segurar parte do lote; count={}",
        resolver.count()
    );

    tokio::time::sleep(Duration::from_millis(1_200)).await;
    assert_eq!(
        resolver.count(),
        3,
        "todo o lote deve drenar eventualmente; count={}",
        resolver.count()
    );
}

#[tokio::test]
async fn test_zero_rate_disables_pacing() {
    // 0 preserva o comportamento anterior: drena tão rápido quanto o worker
    // conseguir, sem espera entre itens.
    let cache = create_refresh_cache();
    let resolver = Arc::new(RecordingResolver::new());
    let (_stale_tx, stale_rx) = mpsc::channel(16);
    let (tx, optimistic_rx) = mpsc::channel(16);

    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        stale_rx,
        optimistic_rx,
        0.0,
    );

    for i in 0..3 {
        tx.send((
            Arc::from(format!("unpaced-{i}.com").as_str()),
            RecordType::A,
        ))
        .await
        .expect("envio falhou");
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        resolver.count(),
        3,
        "sem pacing os 3 devem sair de imediato; count={}",
        resolver.count()
    );
}
