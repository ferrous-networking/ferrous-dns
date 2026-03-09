use dashmap::DashMap;
use rustc_hash::FxBuildHasher;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

/// Limits concurrent TCP/DoT connections per IP address.
///
/// Uses an RAII guard: when a connection is accepted, `try_acquire()` returns
/// a `ConnectionGuard` that decrements the count on drop.
#[derive(Clone)]
pub(crate) struct ConnectionLimiter {
    counts: Arc<DashMap<IpAddr, AtomicU32, FxBuildHasher>>,
    max_per_ip: u32,
}

/// RAII guard that decrements the connection count when the connection closes.
///
/// When `limited` is `false` (unlimited mode), the guard is a no-op on drop.
pub(crate) struct ConnectionGuard {
    counts: Arc<DashMap<IpAddr, AtomicU32, FxBuildHasher>>,
    ip: IpAddr,
    limited: bool,
}

impl ConnectionLimiter {
    /// Creates a new limiter. `max_per_ip = 0` means unlimited.
    pub(crate) fn new(max_per_ip: u32) -> Self {
        Self {
            counts: Arc::new(DashMap::with_hasher(FxBuildHasher)),
            max_per_ip,
        }
    }

    /// Tries to acquire a connection slot for `ip`.
    /// Returns `Some(guard)` if within limit, `None` if the limit is exceeded.
    pub(crate) fn try_acquire(&self, ip: IpAddr) -> Option<ConnectionGuard> {
        if self.max_per_ip == 0 {
            return Some(ConnectionGuard {
                counts: Arc::clone(&self.counts),
                ip,
                limited: false,
            });
        }

        let entry = self.counts.entry(ip).or_insert_with(|| AtomicU32::new(0));
        let prev = entry.value().fetch_add(1, Ordering::Relaxed);

        if prev >= self.max_per_ip {
            entry.value().fetch_sub(1, Ordering::Relaxed);
            return None;
        }

        Some(ConnectionGuard {
            counts: Arc::clone(&self.counts),
            ip,
            limited: true,
        })
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if !self.limited {
            return;
        }
        if let Some(entry) = self.counts.get(&self.ip) {
            let prev = entry.value().fetch_sub(1, Ordering::Relaxed);
            // Release the shard read-lock before the map-level remove.
            drop(entry);
            if prev <= 1 {
                self.counts.remove(&self.ip);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_within_limit() {
        let limiter = ConnectionLimiter::new(2);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let g1 = limiter.try_acquire(ip);
        let g2 = limiter.try_acquire(ip);
        assert!(g1.is_some());
        assert!(g2.is_some());
    }

    #[test]
    fn rejects_over_limit() {
        let limiter = ConnectionLimiter::new(2);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let _g1 = limiter.try_acquire(ip).unwrap();
        let _g2 = limiter.try_acquire(ip).unwrap();
        assert!(limiter.try_acquire(ip).is_none());
    }

    #[test]
    fn guard_drop_frees_slot() {
        let limiter = ConnectionLimiter::new(1);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        {
            let _g = limiter.try_acquire(ip).unwrap();
            assert!(limiter.try_acquire(ip).is_none());
        }
        assert!(limiter.try_acquire(ip).is_some());
    }

    #[test]
    fn unlimited_when_zero() {
        let limiter = ConnectionLimiter::new(0);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        let guards: Vec<_> = (0..100).map(|_| limiter.try_acquire(ip).unwrap()).collect();
        assert_eq!(guards.len(), 100);
    }
}
