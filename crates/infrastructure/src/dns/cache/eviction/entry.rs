use super::super::key::CacheKey;
use std::cmp::Ordering;

#[derive(Clone)]
pub struct EvictionEntry {
    pub key: CacheKey,
    pub score: f64,
    pub last_access: u64,
}

impl PartialEq for EvictionEntry {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
}

impl Eq for EvictionEntry {}

impl PartialOrd for EvictionEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EvictionEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .score
            .partial_cmp(&self.score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.last_access.cmp(&self.last_access))
    }
}
