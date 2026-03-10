/// Port for checking whether a domain has been flagged by the background
/// tunneling analysis task.
///
/// Implemented by the infrastructure layer's `TunnelingDetector`.
/// Called on the hot path — implementations must be O(1) and lock-free.
pub trait TunnelingFlagStore: Send + Sync {
    /// Returns `true` if the domain has been flagged as a tunneling endpoint.
    fn is_flagged(&self, domain: &str) -> bool;
}

/// Port for evicting stale tunneling tracking entries.
///
/// Used by the background eviction job to clean up expired data.
pub trait TunnelingEvictionTarget: Send + Sync + 'static {
    /// Removes stale entries older than the configured TTL.
    fn evict_stale(&self);
    /// Returns the number of currently tracked client/apex pairs.
    fn tracked_count(&self) -> usize;
    /// Returns the number of currently flagged domains.
    fn flagged_count(&self) -> usize;
}
