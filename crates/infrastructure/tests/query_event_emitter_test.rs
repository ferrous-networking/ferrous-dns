use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::cache::coarse_clock::{self, coarse_now_secs};
use ferrous_dns_infrastructure::dns::events::{QueryEvent, QueryEventEmitter};
use std::sync::{mpsc, Arc};
use std::time::Duration;
use tokio::sync::mpsc::error::TryRecvError;
use tracing::field::{Field, Visit};
use tracing_subscriber::{layer::Context, prelude::*, Layer, Registry};

/// `(dropped, total_dropped)` from each drop warning.
struct DropWarnings(mpsc::Sender<(u64, u64)>);

impl Layer<Registry> for DropWarnings {
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, Registry>) {
        if *event.metadata().level() == tracing::Level::WARN {
            let mut counts = DropCounts::default();
            event.record(&mut counts);
            self.0.send((counts.dropped, counts.total)).unwrap();
        }
    }
}

#[derive(Default)]
struct DropCounts {
    dropped: u64,
    total: u64,
}

impl Visit for DropCounts {
    fn record_u64(&mut self, field: &Field, value: u64) {
        match field.name() {
            "dropped" => self.dropped = value,
            "total_dropped" => self.total = value,
            _ => {}
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

fn event(domain: &str) -> QueryEvent {
    QueryEvent {
        domain: Arc::from(domain),
        record_type: RecordType::A,
        upstream_server: Arc::from("127.0.0.1:53"),
        response_time_us: 10,
        success: true,
        pool_name: None,
    }
}

// Nothing in this test binary runs the clock ticker, so time only moves on `tick`.
fn advance_coarse_clock() {
    let start = coarse_now_secs();
    while coarse_now_secs() == start {
        std::thread::sleep(Duration::from_millis(20));
        coarse_clock::tick();
    }
}

#[test]
fn test_overflow_is_lossy_recovers_and_rate_limits_shared_warnings() {
    let (warning_tx, warnings) = mpsc::channel();
    let subscriber = Registry::default().with(DropWarnings(warning_tx));
    let _guard = tracing::subscriber::set_default(subscriber);
    let (emitter, mut receiver) = QueryEventEmitter::new_enabled();
    let cloned = emitter.clone();

    for _ in 0..receiver.max_capacity() {
        emitter.emit(event("retained.example"));
    }
    assert!(matches!(
        warnings.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    // Clones share one budget: the first drop warns, the rest of the second is silent.
    for dropped in 1..=7 {
        let sender = if dropped % 2 == 0 { &emitter } else { &cloned };
        sender.emit(event("dropped.example"));
    }
    assert_eq!(warnings.try_iter().collect::<Vec<_>>(), [(1, 1)]);

    for _ in 0..receiver.max_capacity() {
        assert_eq!(receiver.try_recv().unwrap().domain(), "retained.example");
    }
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));

    cloned.emit(event("recovered.example"));
    assert_eq!(receiver.try_recv().unwrap().domain(), "recovered.example");
    assert!(matches!(receiver.try_recv(), Err(TryRecvError::Empty)));
    assert!(matches!(
        warnings.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));

    // A later episode warns again and carries the drops the silent second absorbed.
    drop(receiver);
    advance_coarse_clock();
    emitter.emit(event("closed.example"));
    assert_eq!(warnings.try_iter().collect::<Vec<_>>(), [(7, 8)]);
}
