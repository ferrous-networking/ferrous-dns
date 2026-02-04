use dashmap::DashMap;
use std::sync::Arc;
use tracing::{debug, info};

/// Prefetch prediction based on query patterns (Markov chain)
pub struct PrefetchPredictor {
    /// Pattern map: domain -> [(next_domain, probability, count)]
    patterns: Arc<DashMap<String, Vec<PredictionEntry>>>,
    
    /// Maximum predictions per domain
    max_predictions: usize,
    
    /// Minimum probability threshold (0.0 to 1.0)
    min_probability: f64,
    
    /// Total predictions tracked
    total_patterns: Arc<std::sync::atomic::AtomicU64>,
}

#[derive(Clone, Debug)]
struct PredictionEntry {
    next_domain: String,
    count: u32,
    probability: f64,
}

impl PrefetchPredictor {
    pub fn new(max_predictions: usize, min_probability: f64) -> Self {
        info!(
            max_predictions = max_predictions,
            min_probability = min_probability,
            "Initializing prefetch predictor"
        );
        
        Self {
            patterns: Arc::new(DashMap::new()),
            max_predictions,
            min_probability,
            total_patterns: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }
    
    /// Record a query pattern (called after each DNS query)
    pub fn record_pattern(&self, previous_domain: Option<&str>, current_domain: &str) {
        if let Some(prev) = previous_domain {
            // Update pattern: prev -> current
            let mut entry = self.patterns.entry(prev.to_string()).or_insert_with(Vec::new);
            
            // Find or create prediction entry
            if let Some(pred) = entry.iter_mut().find(|p| p.next_domain == current_domain) {
                pred.count += 1;
            } else {
                entry.push(PredictionEntry {
                    next_domain: current_domain.to_string(),
                    count: 1,
                    probability: 0.0,  // Will recalculate
                });
            }
            
            // Recalculate probabilities
            let total: u32 = entry.iter().map(|p| p.count).sum();
            for pred in entry.iter_mut() {
                pred.probability = pred.count as f64 / total as f64;
            }
            
            // Sort by probability (highest first) and trim to max_predictions
            entry.sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap());
            entry.truncate(self.max_predictions);
            
            self.total_patterns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            
            debug!(
                prev = %prev,
                current = %current_domain,
                predictions = entry.len(),
                "Recorded query pattern"
            );
        }
    }
    
    /// Get predictions for a domain (returns domains to prefetch)
    pub fn predict(&self, domain: &str) -> Vec<(String, f64)> {
        if let Some(entry) = self.patterns.get(domain) {
            let predictions: Vec<(String, f64)> = entry
                .iter()
                .filter(|p| p.probability >= self.min_probability)
                .map(|p| (p.next_domain.clone(), p.probability))
                .collect();
            
            if !predictions.is_empty() {
                debug!(
                    domain = %domain,
                    predictions = predictions.len(),
                    "Prefetch predictions available"
                );
            }
            
            predictions
        } else {
            Vec::new()
        }
    }
    
    /// Get statistics
    pub fn stats(&self) -> PrefetchStats {
        PrefetchStats {
            total_patterns: self.total_patterns.load(std::sync::atomic::Ordering::Relaxed),
            unique_domains: self.patterns.len() as u64,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PrefetchStats {
    pub total_patterns: u64,
    pub unique_domains: u64,
}

// Thread-local tracker for last queried domain
thread_local! {
    static LAST_DOMAIN: std::cell::RefCell<Option<String>> = std::cell::RefCell::new(None);
}

impl PrefetchPredictor {
    /// Record query and trigger prefetch if needed (call this after every DNS query)
    pub fn on_query(&self, domain: &str) -> Vec<String> {
        // Get previous domain from thread-local storage
        let prev_domain = LAST_DOMAIN.with(|last| last.borrow().clone());
        
        // Record pattern
        self.record_pattern(prev_domain.as_deref(), domain);
        
        // Update last domain
        LAST_DOMAIN.with(|last| {
            *last.borrow_mut() = Some(domain.to_string());
        });
        
        // Get predictions for prefetching
        self.predict(domain)
            .into_iter()
            .map(|(d, _)| d)
            .collect()
    }
}
