//! Testes das filas de refresh em background e do pacer adaptativo.
//!
//! Antes, `run_refresh_cycle` resolvia cada candidato inline e em sequência: o
//! único freio era a latência do upstream, então um resolver local rápido fazia
//! o ciclo renovar toda a working set elegível de uma vez. A primeira tentativa
//! de conserto foi um teto fixo de renovações por segundo — mas teto de taxa não
//! é o mesmo que ausência de rajada, e o teto passou a limitar a vazão total: um
//! cache maior do que `teto * cache_min_ttl` simplesmente deixava de ser
//! renovado.
//!
//! Agora o ciclo apenas varre e enfileira, e o período de drenagem é derivado do
//! backlog: `intervalo_do_ciclo / backlog`. O trabalho de um ciclo se espalha
//! pela janela até o próximo, em qualquer volume, e quem limita a carga
//! instantânea no upstream é o semáforo de concorrência do worker — não o pacer.
//!
//! Serve-stale continua com fila própria e sem pacer: um cliente já recebeu
//! resposta velha e está esperando a boa. As filas são separadas justamente
//! porque uma FIFO única faria o item stale esperar todo o backlog paced.

use async_trait::async_trait;
use ferrous_dns_application::ports::{CacheMaintenancePort, DnsResolution, DnsResolver};
use ferrous_dns_domain::{DnsQuery, DomainError, RecordType};
use ferrous_dns_infrastructure::dns::{
    CachedAddresses, CachedData, DnsCache, DnsCacheConfig, DnsCacheMaintenance, EvictionStrategy,
    RefreshPace, RefreshRequest, RefreshScanOptions, RefreshSenders,
};
use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

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
    create_cache_with(200, 0.0)
}

/// Como `create_refresh_cache`, mas com capacidade e limiar escolhidos pelo
/// teste. `refresh_threshold = 1.0` é o oposto útil: nenhuma entrada viva é
/// considerada devida, o que serve para provar que o worker recusa trabalho.
fn create_cache_with(max_entries: usize, refresh_threshold: f64) -> Arc<DnsCache> {
    Arc::new(DnsCache::new(DnsCacheConfig {
        max_entries,
        eviction_strategy: EvictionStrategy::HitRate,
        min_threshold: 0.0,
        refresh_threshold,
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

/// Opções em que toda entrada classifica como quente: sem triagem, a ordenação
/// fica valendo só pelo prazo. É o caso normal — a triagem só existe para
/// escolher quem fica de fora quando o backlog não cabe.
fn permissive_opts() -> RefreshScanOptions {
    RefreshScanOptions {
        min_lead_secs: 0,
        min_hit_rate: 0.0,
        min_frequency: 0,
    }
}

/// Opções que separam quente de frio: um único hit basta para uma entrada
/// passar nos dois critérios, zero hits reprova em ambos.
fn hot_cold_opts() -> RefreshScanOptions {
    RefreshScanOptions {
        min_lead_secs: 0,
        min_hit_rate: 1.0,
        min_frequency: 1,
    }
}

/// Monta o adaptador de manutenção junto com o canal de ritmo que ele publica.
fn maintenance_with_pace(
    cache: &Arc<DnsCache>,
    interval_secs: u64,
    opts: RefreshScanOptions,
) -> (DnsCacheMaintenance, watch::Receiver<RefreshPace>) {
    let (pace_tx, pace_rx) = watch::channel(None);
    (
        DnsCacheMaintenance::new(Arc::clone(cache), interval_secs, opts, pace_tx),
        pace_rx,
    )
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

/// Insere uma entrada que não passa pelo L1.
///
/// `insert` promove endereços IP para o cache thread-local, e a partir daí todo
/// `get` é absorvido lá — sem tocar o `hit_count` do registro em L2. Um
/// `CanonicalName` não é promovido, então cada `get` conta um hit de verdade,
/// que é o que a triagem quente/frio lê.
fn insert_countable_entry(cache: &DnsCache, domain: &str) {
    cache.insert(
        domain,
        RecordType::A,
        CachedData::CanonicalName(Arc::from("alvo.com")),
        300,
        None,
    );
}

fn drain_domains(rx: &mut mpsc::Receiver<RefreshRequest>) -> Vec<String> {
    let mut drained = Vec::new();
    while let Ok((domain, _)) = rx.try_recv() {
        drained.push(domain.to_string());
    }
    drained
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

    let (maintenance, _pace_rx) = maintenance_with_pace(&cache, 60, permissive_opts());
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");

    assert_eq!(outcome.candidates_found, 5);
    assert_eq!(outcome.enqueued, 5, "todos os candidatos devem ser aceitos");
    assert_eq!(outcome.dropped, 0);
    assert_eq!(outcome.shed, 0);

    let queued = drain_domains(&mut rx);
    assert_eq!(
        queued.len(),
        5,
        "os 5 candidatos devem estar na fila; queued={queued:?}"
    );
}

#[tokio::test]
async fn test_cycle_without_worker_does_not_strand_entries() {
    // Sem sender configurado nada drenaria a fila, então o ciclo precisa
    // liberar as flags em vez de deixar as entradas marcadas para sempre.
    let cache = create_refresh_cache();
    insert_entries(&cache, 3);

    let (maintenance, _pace_rx) = maintenance_with_pace(&cache, 60, permissive_opts());
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");

    assert_eq!(outcome.candidates_found, 3);
    assert_eq!(outcome.enqueued, 0);
    assert_eq!(
        outcome.paced_period_ms, None,
        "sem nada enfileirado não há ritmo a publicar"
    );

    let again = cache.get_refresh_candidates(&permissive_opts());
    assert_eq!(
        again.len(),
        3,
        "sem worker, as entradas devem continuar elegíveis; again={again:?}"
    );
}

#[tokio::test]
async fn test_cycle_period_divides_interval_by_backlog() {
    // O ritmo não é configurado: sai da divisão do intervalo do ciclo pelo que
    // ficou na fila. 60s para 6 itens = um a cada 10s.
    let cache = create_refresh_cache();
    let (_stale_rx, _rx) = wire_queues(&cache, 8, 128);
    insert_entries(&cache, 6);

    let (maintenance, pace_rx) = maintenance_with_pace(&cache, 60, permissive_opts());
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");

    assert_eq!(outcome.enqueued, 6);
    assert_eq!(
        outcome.paced_period_ms,
        Some(10_000),
        "60s divididos por 6 itens; outcome={outcome:?}"
    );
    assert_eq!(
        *pace_rx.borrow(),
        Some(Duration::from_secs(10)),
        "o worker precisa enxergar o mesmo período que o ciclo reportou"
    );
}

#[tokio::test]
async fn test_cycle_period_is_recomputed_between_cycles() {
    // O período acompanha o backlog vivo, não é fixado na construção. O segundo
    // ciclo enfileira dez vezes mais e o intervalo entre drenagens encolhe na
    // mesma proporção — é isso que faz a vazão seguir a demanda.
    let cache = create_refresh_cache();
    let (_stale_rx, _rx) = wire_queues(&cache, 8, 128);
    insert_entries(&cache, 6);

    let (maintenance, _pace_rx) = maintenance_with_pace(&cache, 60, permissive_opts());
    let first = maintenance
        .run_refresh_cycle()
        .await
        .expect("primeiro ciclo falhou");
    assert_eq!(first.paced_period_ms, Some(10_000));

    // Mais 54 entradas sem drenar nada: as 6 anteriores seguem na fila e com a
    // flag posta, então só as novas viram candidatas — mas o backlog somado é 60.
    for i in 6..60 {
        cache.insert(
            &format!("queued-{i}.com"),
            RecordType::A,
            make_ip_data("1.2.3.4"),
            300,
            None,
        );
    }

    let second = maintenance
        .run_refresh_cycle()
        .await
        .expect("segundo ciclo falhou");

    assert_eq!(
        second.candidates_found, 54,
        "as 6 já enfileiradas não podem ser oferecidas de novo"
    );
    assert_eq!(
        second.paced_period_ms,
        Some(1_000),
        "60s divididos pelos 60 agora na fila; second={second:?}"
    );
}

#[tokio::test]
async fn test_empty_cycle_publishes_no_pacing() {
    // Sem candidatos não há o que espalhar: o worker volta a drenar livremente
    // em vez de herdar o período do ciclo anterior.
    let cache = create_refresh_cache();
    let (_stale_rx, _rx) = wire_queues(&cache, 8, 64);

    let (maintenance, pace_rx) = maintenance_with_pace(&cache, 60, permissive_opts());
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");

    assert_eq!(outcome.candidates_found, 0);
    assert_eq!(outcome.paced_period_ms, None);
    assert_eq!(*pace_rx.borrow(), None);
}

#[tokio::test]
async fn test_sub_millisecond_period_disables_pacing() {
    // Abaixo de 1ms o timer não honra o intervalo de qualquer jeito, e um
    // backlog que exige essa taxa já está espalhado muito além do que o limite
    // de concorrência permite sair de uma vez. 1s / 1001 = 999µs.
    let cache = create_cache_with(4_000, 0.0);
    let (_stale_rx, _rx) = wire_queues(&cache, 8, 2_048);
    insert_entries(&cache, 1_001);

    let (maintenance, pace_rx) = maintenance_with_pace(&cache, 1, permissive_opts());
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");

    assert_eq!(outcome.enqueued, 1_001, "a fila comporta todos");
    assert_eq!(
        outcome.paced_period_ms, None,
        "período sub-milissegundo desliga o pacer; outcome={outcome:?}"
    );
    assert_eq!(*pace_rx.borrow(), None);
}

#[tokio::test]
async fn test_backlog_drains_within_the_interval() {
    // A regressão que importa. Com o teto fixo de 4/s, 40 itens levavam 10
    // segundos e um cache maior que `4 * cache_min_ttl` nunca fechava o ciclo.
    // Agora o período sai de 1s/40 = 25ms e o lote inteiro cabe no intervalo.
    let cache = create_refresh_cache();
    let resolver = Arc::new(RecordingResolver::new());
    let (_stale_rx, optimistic_rx) = wire_queues(&cache, 16, 128);
    let (stale_tx, worker_stale_rx) = mpsc::channel(16);
    insert_entries(&cache, 40);

    let (pace_tx, pace_rx) = watch::channel(None);
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        worker_stale_rx,
        optimistic_rx,
        pace_rx,
        0,
    );
    drop(stale_tx);

    let maintenance = DnsCacheMaintenance::new(Arc::clone(&cache), 1, permissive_opts(), pace_tx);
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");
    assert_eq!(outcome.enqueued, 40);
    assert_eq!(outcome.paced_period_ms, Some(25));

    // Cedo demais para ter saído tudo: prova que continua espalhado, não é rajada.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        resolver.count() < 40,
        "o lote não pode sair de uma vez; count={}",
        resolver.count()
    );

    tokio::time::sleep(Duration::from_millis(1_300)).await;
    assert_eq!(
        resolver.count(),
        40,
        "todo o backlog deve drenar dentro do intervalo; count={}",
        resolver.count()
    );
}

#[tokio::test]
async fn test_overflow_sheds_cold_entries_before_hot_ones() {
    // Quando o backlog não cabe, o corte é por valor e não por ordem de
    // iteração do mapa. Antes, a cauda da varredura era descartada ciclo após
    // ciclo — sempre as mesmas entradas, porque a ordem do DashMap é estável.
    let cache = create_cache_with(200, 0.0);
    let (_stale_rx, mut rx) = wire_queues(&cache, 8, 3);

    let hot = ["quente-0.com", "quente-1.com", "quente-2.com"];
    let cold = [
        "fria-0.com",
        "fria-1.com",
        "fria-2.com",
        "fria-3.com",
        "fria-4.com",
    ];

    for domain in hot.iter().chain(cold.iter()) {
        insert_countable_entry(&cache, domain);
    }
    // Um único acesso já separa quente de frio nos dois critérios da triagem.
    for domain in &hot {
        cache
            .get(domain, &RecordType::A)
            .expect("a entrada recém inserida deve estar no cache");
    }

    let (maintenance, _pace_rx) = maintenance_with_pace(&cache, 60, hot_cold_opts());
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");

    assert_eq!(outcome.candidates_found, 8);
    assert_eq!(outcome.enqueued, 3, "a fila só comporta 3");
    assert_eq!(
        outcome.shed, 5,
        "os 5 excedentes são cortados antes de tentar"
    );
    assert_eq!(
        outcome.dropped, 0,
        "o corte antecipado evita recusa da fila"
    );

    let queued = drain_domains(&mut rx);
    for domain in &queued {
        assert!(
            hot.contains(&domain.as_str()),
            "só as entradas quentes podem passar; queued={queued:?}"
        );
    }

    // Os cortados não podem ficar presos na flag de fila: precisam voltar a ser
    // candidatos no ciclo seguinte. Os 3 enfileirados seguem marcados.
    let again = cache.get_refresh_candidates(&hot_cold_opts());
    assert_eq!(
        again.len(),
        5,
        "os cortados devem seguir elegíveis; again={again:?}"
    );
    for (domain, _) in &again {
        assert!(
            cold.contains(&domain.as_str()),
            "um candidato já enfileirado não pode reaparecer; domain={domain}"
        );
    }
}

#[tokio::test]
async fn test_nothing_is_shed_when_the_backlog_fits() {
    // A triagem quente/frio é política de escassez: com espaço na fila ela não
    // pode tirar cobertura de ninguém, nem das entradas nunca acessadas.
    let cache = create_cache_with(200, 0.0);
    let (_stale_rx, mut rx) = wire_queues(&cache, 8, 64);

    for i in 0..8 {
        insert_countable_entry(&cache, &format!("fria-{i}.com"));
    }

    let (maintenance, _pace_rx) = maintenance_with_pace(&cache, 60, hot_cold_opts());
    let outcome = maintenance
        .run_refresh_cycle()
        .await
        .expect("ciclo de refresh falhou");

    assert_eq!(outcome.candidates_found, 8);
    assert_eq!(outcome.enqueued, 8, "todas passam quando há espaço");
    assert_eq!(outcome.shed, 0);
    assert_eq!(drain_domains(&mut rx).len(), 8);
}

#[tokio::test]
async fn test_dequeue_skips_entry_that_no_longer_needs_refresh() {
    // Um item pode ficar quase um ciclo inteiro na fila, tempo suficiente para
    // um reparo serve-stale já ter renovado a entrada. Ao sair da fila o worker
    // reconfere antes de gastar consulta upstream — aqui o limiar de 1.0 põe
    // toda entrada viva fora do prazo de renovação.
    let cache = create_cache_with(200, 1.0);
    let resolver = Arc::new(RecordingResolver::new());
    let (_stale_tx, stale_rx) = mpsc::channel(16);
    let (tx, optimistic_rx) = mpsc::channel(16);
    insert_entries(&cache, 1);

    let (_pace_tx, pace_rx) = watch::channel(None);
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        stale_rx,
        optimistic_rx,
        pace_rx,
        0,
    );

    tx.send((Arc::from("queued-0.com"), RecordType::A))
        .await
        .expect("envio falhou");
    // Um domínio que sumiu do cache enquanto esperava também não pode virar
    // consulta: não há registro para renovar.
    tx.send((Arc::from("inexistente.com"), RecordType::A))
        .await
        .expect("envio falhou");

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(
        resolver.count(),
        0,
        "nada devido não pode virar consulta upstream; calls={:?}",
        resolver.calls.lock().expect("mutex envenenado")
    );
}

#[tokio::test]
async fn test_dequeue_resolves_entry_that_still_needs_refresh() {
    // Controle do teste anterior: a reconferência recusa trabalho inútil, mas
    // não pode recusar trabalho legítimo.
    let cache = create_cache_with(200, 0.0);
    let resolver = Arc::new(RecordingResolver::new());
    let (_stale_tx, stale_rx) = mpsc::channel(16);
    let (tx, optimistic_rx) = mpsc::channel(16);
    insert_entries(&cache, 1);

    let (_pace_tx, pace_rx) = watch::channel(None);
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        stale_rx,
        optimistic_rx,
        pace_rx,
        0,
    );

    tx.send((Arc::from("queued-0.com"), RecordType::A))
        .await
        .expect("envio falhou");

    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(
        resolver.saw("queued-0.com"),
        "a entrada devida precisa ser renovada; calls={:?}",
        resolver.calls.lock().expect("mutex envenenado")
    );
}

#[tokio::test]
async fn test_stale_refresh_bypasses_the_pacer() {
    // Com um período de 5s o worker fica dormindo antes mesmo de olhar a fila
    // optimistic. O braço stale é polido primeiro a cada volta, então um reparo
    // enfileirado nesse meio tempo sai na hora.
    let cache = create_cache_with(200, 0.0);
    let resolver = Arc::new(RecordingResolver::new());
    let (stale_tx, stale_rx) = mpsc::channel(16);
    let (optimistic_tx, optimistic_rx) = mpsc::channel(16);
    insert_entries(&cache, 1);

    let (_pace_tx, pace_rx) = watch::channel(Some(Duration::from_secs(5)));
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        stale_rx,
        optimistic_rx,
        pace_rx,
        0,
    );

    optimistic_tx
        .send((Arc::from("queued-0.com"), RecordType::A))
        .await
        .expect("envio do optimistic falhou");
    tokio::time::sleep(Duration::from_millis(100)).await;

    stale_tx
        .send((Arc::from("urgente.com"), RecordType::A))
        .await
        .expect("envio do stale falhou");
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        resolver.saw("urgente.com"),
        "um refresh stale não pode esperar o pacer; calls={:?}",
        resolver.calls.lock().expect("mutex envenenado")
    );
    assert!(
        !resolver.saw("queued-0.com"),
        "o item optimistic ainda está dentro do período; calls={:?}",
        resolver.calls.lock().expect("mutex envenenado")
    );
}

#[tokio::test]
async fn test_stale_refresh_does_not_wait_behind_optimistic_backlog() {
    // Regressão da fila única: com um backlog optimistic grande sendo espalhado,
    // um item stale enfileirado *depois* dele precisa sair de imediato. Numa
    // FIFO compartilhada o worker ficaria parado no período do primeiro
    // optimistic e o stale só seria visto depois de todo o lote.
    let cache = create_cache_with(200, 0.0);
    let resolver = Arc::new(RecordingResolver::new());
    let (stale_tx, stale_rx) = mpsc::channel(16);
    let (optimistic_tx, optimistic_rx) = mpsc::channel(64);
    insert_entries(&cache, 40);

    let (_pace_tx, pace_rx) = watch::channel(Some(Duration::from_millis(500)));
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        stale_rx,
        optimistic_rx,
        pace_rx,
        0,
    );

    // 40 itens a um a cada 500ms = 20 segundos de backlog.
    for i in 0..40 {
        optimistic_tx
            .send((Arc::from(format!("queued-{i}.com").as_str()), RecordType::A))
            .await
            .expect("envio do backlog falhou");
    }

    tokio::time::sleep(Duration::from_millis(100)).await;

    stale_tx
        .send((Arc::from("urgente.com"), RecordType::A))
        .await
        .expect("envio do stale falhou");
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        resolver.saw("urgente.com"),
        "o stale não pode esperar o backlog paced drenar; calls={:?}",
        resolver.calls.lock().expect("mutex envenenado")
    );
    assert!(
        resolver.count() < 40,
        "o backlog optimistic deve seguir espalhado; count={}",
        resolver.count()
    );
}

#[tokio::test]
async fn test_optimistic_refresh_honours_the_published_period() {
    // 250ms entre itens: três optimistic não podem sair todos de uma vez, mas
    // todos precisam sair no fim.
    let cache = create_cache_with(200, 0.0);
    let resolver = Arc::new(RecordingResolver::new());
    let (_stale_tx, stale_rx) = mpsc::channel(16);
    let (tx, optimistic_rx) = mpsc::channel(16);
    insert_entries(&cache, 3);

    let (_pace_tx, pace_rx) = watch::channel(Some(Duration::from_millis(250)));
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        stale_rx,
        optimistic_rx,
        pace_rx,
        0,
    );

    for i in 0..3 {
        tx.send((Arc::from(format!("queued-{i}.com").as_str()), RecordType::A))
            .await
            .expect("envio falhou");
    }

    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        resolver.count() < 3,
        "o período deve segurar parte do lote; count={}",
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
async fn test_absent_period_disables_pacing() {
    // `None` é o que um ciclo vazio publica: sem backlog para espalhar, o worker
    // drena tão rápido quanto conseguir.
    let cache = create_cache_with(200, 0.0);
    let resolver = Arc::new(RecordingResolver::new());
    let (_stale_tx, stale_rx) = mpsc::channel(16);
    let (tx, optimistic_rx) = mpsc::channel(16);
    insert_entries(&cache, 3);

    let (_pace_tx, pace_rx) = watch::channel(None);
    DnsCacheMaintenance::start_refresh_worker(
        Arc::clone(&cache),
        Arc::clone(&resolver) as Arc<dyn DnsResolver>,
        None,
        stale_rx,
        optimistic_rx,
        pace_rx,
        0,
    );

    for i in 0..3 {
        tx.send((Arc::from(format!("queued-{i}.com").as_str()), RecordType::A))
            .await
            .expect("envio falhou");
    }

    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        resolver.count(),
        3,
        "sem período os 3 devem sair de imediato; count={}",
        resolver.count()
    );
}
