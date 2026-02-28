use compact_str::CompactString;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

struct PatternMsg {
    previous: CompactString,
    current: CompactString,
}

pub struct PrefetchPredictor {
    patterns: Arc<DashMap<CompactString, Vec<PredictionEntry>>>,
    min_probability: f64,
    total_patterns: Arc<std::sync::atomic::AtomicU64>,
    sender: mpsc::Sender<PatternMsg>,
}

#[derive(Clone, Debug)]
struct PredictionEntry {
    next_domain: CompactString,
    count: u32,
    probability: f64,
}

impl PrefetchPredictor {
    pub fn new(max_predictions: usize, min_probability: f64) -> Self {
        info!(
            max_predictions,
            min_probability, "Initializing prefetch predictor"
        );
        let patterns = Arc::new(DashMap::new());
        let total_patterns = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (sender, receiver) = mpsc::channel(4096);

        let bg_patterns = Arc::clone(&patterns);
        let bg_total = Arc::clone(&total_patterns);
        tokio::spawn(Self::pattern_loop(
            receiver,
            bg_patterns,
            bg_total,
            max_predictions,
        ));

        Self {
            patterns,
            min_probability,
            total_patterns,
            sender,
        }
    }

    async fn pattern_loop(
        mut receiver: mpsc::Receiver<PatternMsg>,
        patterns: Arc<DashMap<CompactString, Vec<PredictionEntry>>>,
        total_patterns: Arc<std::sync::atomic::AtomicU64>,
        max_predictions: usize,
    ) {
        while let Some(msg) = receiver.recv().await {
            let mut entry = patterns.entry(msg.previous).or_default();
            if let Some(pred) = entry.iter_mut().find(|p| p.next_domain == msg.current) {
                pred.count += 1;
            } else {
                entry.push(PredictionEntry {
                    next_domain: msg.current,
                    count: 1,
                    probability: 0.0,
                });
            }
            let total: u32 = entry.iter().map(|p| p.count).sum();
            for pred in entry.iter_mut() {
                pred.probability = pred.count as f64 / total as f64;
            }
            entry.sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap());
            entry.truncate(max_predictions);
            total_patterns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    fn record_pattern(&self, previous_domain: Option<&str>, current_domain: &str) {
        if let Some(prev) = previous_domain {
            let msg = PatternMsg {
                previous: CompactString::from(prev),
                current: CompactString::from(current_domain),
            };
            if self.sender.try_send(msg).is_err() {
                warn!("Prefetch pattern channel full, dropping pattern");
            }
        }
    }

    pub fn predict(&self, domain: &str) -> Vec<(CompactString, f64)> {
        let key = CompactString::from(domain);
        if let Some(entry) = self.patterns.get(&key) {
            let predictions: Vec<(CompactString, f64)> = entry
                .iter()
                .filter(|p| p.probability >= self.min_probability)
                .map(|p| (p.next_domain.clone(), p.probability))
                .collect();
            if !predictions.is_empty() {
                debug!(domain = %domain, predictions = predictions.len(), "Prefetch predictions available");
            }
            predictions
        } else {
            Vec::new()
        }
    }

    pub fn stats(&self) -> PrefetchStats {
        PrefetchStats {
            total_patterns: self
                .total_patterns
                .load(std::sync::atomic::Ordering::Relaxed),
            unique_domains: self.patterns.len() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrefetchStats {
    pub total_patterns: u64,
    pub unique_domains: u64,
}

thread_local! {
    static LAST_DOMAIN: std::cell::RefCell<Option<CompactString>> = const { std::cell::RefCell::new(None) };
}

impl PrefetchPredictor {
    pub fn on_query(&self, domain: &str) {
        LAST_DOMAIN.with(|last| {
            {
                let borrowed = last.borrow();
                self.record_pattern(borrowed.as_deref(), domain);
            }
            *last.borrow_mut() = Some(CompactString::from(domain));
        });
    }
}
