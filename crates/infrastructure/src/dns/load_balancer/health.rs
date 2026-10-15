use crate::dns::forwarding::{MessageBuilder, ResponseParser};
use crate::dns::transport;
use dashmap::DashMap;
use ferrous_dns_domain::{DnsProtocol, RecordType};
use rustc_hash::FxBuildHasher;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ServerStatus {
    Healthy,
    Unhealthy,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default)]
pub struct ServerHealth {
    pub status: ServerStatus,
    pub consecutive_failures: u16,
    pub consecutive_successes: u16,
    pub last_check_latency_ms: Option<u64>,
    pub last_error: Option<String>,
}

pub struct HealthChecker {
    health_map: DashMap<Arc<DnsProtocol>, ServerHealth, FxBuildHasher>,
    failure_threshold: u8,
    success_threshold: u8,
}

/// A server to probe, and the zone it answers when it answers only some
/// domains: a conditional pool's server, which may well refuse `google.com`.
pub type HealthProbe = (Arc<DnsProtocol>, Option<Arc<str>>);

/// What a server that answers every name is asked.
const DEFAULT_PROBE_NAME: &str = "google.com";

impl HealthChecker {
    pub fn new(failure_threshold: u8, success_threshold: u8) -> Self {
        Self {
            health_map: DashMap::with_hasher(FxBuildHasher),
            failure_threshold,
            success_threshold,
        }
    }

    /// Runs the periodic probe loop. `protocols_provider` is called once per tick
    /// to obtain the current set of servers, so upstreams added through a live pool
    /// reload start getting health-checked without a restart.
    pub async fn run<F>(
        self: Arc<Self>,
        protocols_provider: F,
        interval_seconds: u64,
        timeout_ms: u64,
    ) where
        F: Fn() -> Vec<Arc<DnsProtocol>> + Send + 'static,
    {
        self.run_probes(
            move || {
                protocols_provider()
                    .into_iter()
                    .map(|p| (p, None))
                    .collect()
            },
            interval_seconds,
            timeout_ms,
        )
        .await
    }

    /// [`Self::run`] for servers that may answer only their own zone: each one
    /// is asked for that zone's SOA instead of `google.com`.
    pub async fn run_probes<F>(
        self: Arc<Self>,
        probes_provider: F,
        interval_seconds: u64,
        timeout_ms: u64,
    ) where
        F: Fn() -> Vec<HealthProbe> + Send + 'static,
    {
        let initial = probes_provider();
        info!(
            servers = initial.len(),
            interval_seconds, "Health checker running"
        );

        let self_clone = Arc::clone(&self);
        tokio::spawn(async move {
            self_clone.check_all(&initial, timeout_ms).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut check_interval = interval(Duration::from_secs(interval_seconds));
        loop {
            check_interval.tick().await;
            // Re-fetch the live protocol set each tick so servers added via a hot
            // pool reload are probed, and removed servers stop being probed.
            let probes = probes_provider();
            // Drop health entries for servers no longer in the live set, so removed
            // upstreams stop being reported as healthy/unhealthy and rotating
            // hostname IPs don't accumulate stale entries across reloads.
            self.retain_live(&probes);
            self.check_all(&probes, timeout_ms).await;
        }
    }

    /// Removes health entries whose server is no longer in `protocols`. Called once
    /// per tick with the live pool set so a hot reload that drops a server — or
    /// re-resolves a hostname to fresh addresses — doesn't leave its status lingering
    /// in the map nor let the map grow unbounded across reloads.
    fn retain_live(&self, probes: &[HealthProbe]) {
        let live: HashSet<Arc<DnsProtocol>> = probes.iter().map(|(p, _)| Arc::clone(p)).collect();
        self.health_map.retain(|k, _| live.contains(k));
    }

    async fn check_all(&self, probes: &[HealthProbe], timeout_ms: u64) {
        let Ok(default_query) =
            MessageBuilder::build_query(DEFAULT_PROBE_NAME, &RecordType::A, false)
        else {
            return;
        };
        let queries: Vec<Vec<u8>> = probes
            .iter()
            .map(|(_, zone)| {
                zone.as_deref()
                    .and_then(|zone| {
                        MessageBuilder::build_query(zone, &RecordType::SOA, false).ok()
                    })
                    .unwrap_or_else(|| default_query.clone())
            })
            .collect();
        let futs: Vec<_> = probes
            .iter()
            .zip(&queries)
            .map(|((p, _), query)| self.check_server(p, query, timeout_ms))
            .collect();
        futures::future::join_all(futs).await;
    }

    async fn check_server(&self, protocol: &Arc<DnsProtocol>, query_bytes: &[u8], timeout_ms: u64) {
        let start = std::time::Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);

        let dns_transport = match transport::get_or_create_transport(protocol) {
            Ok(t) => t,
            Err(e) => {
                self.mark_failed(protocol, None, e.to_string());
                return;
            }
        };

        let result = tokio::time::timeout(
            timeout_duration,
            dns_transport.send(query_bytes, timeout_duration),
        )
        .await;
        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Err(_) => {
                warn!(server = %protocol, "Health check: TIMEOUT");
                self.mark_failed(protocol, None, format!("Timeout after {}ms", timeout_ms));
            }
            Ok(Err(e)) => {
                warn!(server = %protocol, error = %e, "Health check: FAILED");
                self.mark_failed(protocol, Some(latency_ms), e.to_string());
            }
            Ok(Ok(resp)) => match ResponseParser::parse_bytes(resp) {
                Ok(dns) if dns.is_server_error() => {
                    self.mark_failed(
                        protocol,
                        Some(latency_ms),
                        ResponseParser::rcode_to_status(dns.rcode).to_string(),
                    );
                }
                Ok(_) => {
                    debug!(server = %protocol, latency_ms, "Health check: OK");
                    self.mark_healthy(protocol, latency_ms);
                }
                Err(e) => {
                    self.mark_failed(protocol, Some(latency_ms), e.to_string());
                }
            },
        }
    }

    fn mark_healthy(&self, protocol: &Arc<DnsProtocol>, latency_ms: u64) {
        let mut entry = self.health_map.entry(Arc::clone(protocol)).or_default();
        entry.consecutive_failures = 0;
        entry.consecutive_successes = entry.consecutive_successes.saturating_add(1);
        entry.last_check_latency_ms = Some(latency_ms);
        entry.last_error = None;
        if entry.consecutive_successes >= self.success_threshold as u16 {
            if entry.status != ServerStatus::Healthy {
                info!(server = %protocol, latency_ms, "Server marked HEALTHY");
            }
            entry.status = ServerStatus::Healthy;
        }
    }

    fn mark_failed(&self, protocol: &Arc<DnsProtocol>, latency_ms: Option<u64>, error: String) {
        let mut entry = self.health_map.entry(Arc::clone(protocol)).or_default();
        entry.consecutive_successes = 0;
        entry.consecutive_failures = entry.consecutive_failures.saturating_add(1);
        entry.last_check_latency_ms = latency_ms;
        entry.last_error = Some(error);
        if entry.consecutive_failures >= self.failure_threshold as u16 {
            if entry.status != ServerStatus::Unhealthy {
                warn!(server = %protocol, "Server marked UNHEALTHY");
            }
            entry.status = ServerStatus::Unhealthy;
        }
    }

    pub fn is_healthy(&self, protocol: &Arc<DnsProtocol>) -> bool {
        // Unknown stays in rotation: a server leaves only after failure_threshold failures.
        self.health_map
            .get(protocol)
            .map(|h| match h.status {
                ServerStatus::Healthy | ServerStatus::Unknown => true,
                ServerStatus::Unhealthy => false,
            })
            .unwrap_or(true)
    }

    pub fn get_status(&self, protocol: &Arc<DnsProtocol>) -> ServerStatus {
        self.health_map
            .get(protocol)
            .map(|h| h.status)
            .unwrap_or_default()
    }

    pub fn get_health_info(&self, protocol: &Arc<DnsProtocol>) -> Option<ServerHealth> {
        self.health_map.get(protocol).map(|h| h.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto() -> Arc<DnsProtocol> {
        Arc::new("udp://127.0.0.1:53".parse::<DnsProtocol>().unwrap())
    }

    #[test]
    fn server_stays_in_rotation_until_failure_threshold() {
        let checker = HealthChecker::new(3, 1);
        let server = proto();

        checker.mark_failed(&server, None, "timeout".into());
        checker.mark_failed(&server, None, "timeout".into());
        assert_eq!(checker.get_status(&server), ServerStatus::Unknown);
        assert!(
            checker.is_healthy(&server),
            "below threshold must stay in rotation"
        );

        checker.mark_failed(&server, None, "timeout".into());
        assert_eq!(checker.get_status(&server), ServerStatus::Unhealthy);
        assert!(!checker.is_healthy(&server));
    }
}
