use compact_str::CompactString;
use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Prefetch prediction based on query patterns (Markov chain).
/// Uses CompactString — domains ≤24 bytes live inline on stack.
pub struct PrefetchPredictor {
    patterns: Arc<DashMap<CompactString, Vec<PredictionEntry>>>,
    max_predictions: usize,
    min_probability: f64,
    total_patterns: Arc<std::sync::atomic::AtomicU64>,
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
        Self {
            patterns: Arc::new(DashMap::new()),
            max_predictions,
            min_probability,
            total_patterns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn record_pattern(&self, previous_domain: Option<&str>, current_domain: &str) {
        if let Some(prev) = previous_domain {
            let key = CompactString::from(prev);
            let mut entry = self.patterns.entry(key).or_default();
            if let Some(pred) = entry
                .iter_mut()
                .find(|p| p.next_domain.as_str() == current_domain)
            {
                pred.count += 1;
            } else {
                entry.push(PredictionEntry {
                    next_domain: CompactString::from(current_domain),
                    count: 1,
                    probability: 0.0,
                });
            }
            let total: u32 = entry.iter().map(|p| p.count).sum();
            for pred in entry.iter_mut() {
                pred.probability = pred.count as f64 / total as f64;
            }
            entry.sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap());
            entry.truncate(self.max_predictions);
            self.total_patterns
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            debug!(prev = %prev, current = %current_domain, predictions = entry.len(), "Recorded query pattern");
        }
    }

    pub fn predict(&self, domain: &str) -> Vec<(String, f64)> {
        let key = CompactString::from(domain);
        if let Some(entry) = self.patterns.get(&key) {
            let predictions: Vec<(String, f64)> = entry
                .iter()
                .filter(|p| p.probability >= self.min_probability)
                .map(|p| (p.next_domain.to_string(), p.probability))
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
    pub fn on_query(&self, domain: &str) -> Vec<String> {
        let prev_domain = LAST_DOMAIN.with(|last| last.borrow().as_ref().map(|s| s.to_string()));
        self.record_pattern(prev_domain.as_deref(), domain);
        LAST_DOMAIN.with(|last| {
            *last.borrow_mut() = Some(CompactString::from(domain));
        });
        self.predict(domain).into_iter().map(|(d, _)| d).collect()
    }
}
