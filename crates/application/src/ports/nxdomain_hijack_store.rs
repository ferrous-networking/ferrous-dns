use std::net::IpAddr;

/// Hot-path: O(1) check if an IP is a known NXDomain hijack IP.
///
/// Implemented by the infrastructure layer's `NxdomainHijackDetector`.
/// Called on the hot path — implementations must be O(1) and lock-free.
pub trait NxdomainHijackIpStore: Send + Sync {
    /// Returns `true` if the IP belongs to an ISP's NXDomain hijack server.
    fn is_hijack_ip(&self, ip: &IpAddr) -> bool;
}

/// Background job: eviction of stale hijack IPs and status reporting.
///
/// Used by the background eviction job to clean up expired data.
pub trait NxdomainHijackProbeTarget: Send + Sync + 'static {
    /// Removes hijack IPs not re-confirmed within the configured TTL.
    fn evict_stale_ips(&self);
    /// Returns the number of currently known hijack IPs.
    fn hijack_ip_count(&self) -> usize;
    /// Returns the number of upstreams currently detected as hijacking.
    fn hijacking_upstream_count(&self) -> usize;
}
