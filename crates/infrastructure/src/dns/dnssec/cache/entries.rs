use std::time::{Duration, Instant};

/// A cached, already-authenticated lookup result with its expiry.
#[derive(Debug, Clone)]
pub struct CacheEntry<V> {
    value: V,
    expires_at: Instant,
}

impl<V> CacheEntry<V> {
    pub fn new(value: V, ttl_secs: u32) -> Self {
        Self {
            value,
            expires_at: Instant::now() + Duration::from_secs(u64::from(ttl_secs)),
        }
    }

    pub fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    pub fn get(&self) -> &V {
        &self.value
    }
}
