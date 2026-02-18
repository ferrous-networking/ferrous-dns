use crate::dns::forwarding::{MessageBuilder, ResponseParser};
use crate::dns::transport;
use dashmap::DashMap;
use ferrous_dns_domain::{DnsProtocol, RecordType};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct ServerHealth {
    pub status: ServerStatus,
    pub consecutive_failures: u8,
    pub consecutive_successes: u8,
    pub last_check_latency_ms: Option<u64>,
    pub last_error: Option<String>,
}

impl Default for ServerHealth {
    fn default() -> Self {
        Self {
            status: ServerStatus::Unknown,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_check_latency_ms: None,
            last_error: None,
        }
    }
}

pub struct HealthChecker {
    health_map: Arc<DashMap<String, ServerHealth>>,
    failure_threshold: u8,
    success_threshold: u8,
}

impl HealthChecker {
    pub fn new(failure_threshold: u8, success_threshold: u8) -> Self {
        Self {
            health_map: Arc::new(DashMap::new()),
            failure_threshold,
            success_threshold,
        }
    }

    pub async fn run(
        self: Arc<Self>,
        protocols: Vec<DnsProtocol>,
        interval_seconds: u64,
        timeout_ms: u64,
    ) {
        info!(
            servers = protocols.len(),
            interval_seconds, "Health checker running"
        );

        let self_clone = Arc::clone(&self);
        let protocols_clone = protocols.clone();
        tokio::spawn(async move {
            self_clone.check_all(&protocols_clone, timeout_ms).await;
        });

        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut check_interval = interval(Duration::from_secs(interval_seconds));
        loop {
            check_interval.tick().await;
            self.check_all(&protocols, timeout_ms).await;
        }
    }

    async fn check_all(&self, protocols: &[DnsProtocol], timeout_ms: u64) {
        for protocol in protocols {
            self.check_server(protocol.clone(), timeout_ms).await;
        }
    }

    async fn check_server(&self, protocol: DnsProtocol, timeout_ms: u64) {
        let server_str = protocol.to_string();
        let start = std::time::Instant::now();
        let timeout_duration = Duration::from_millis(timeout_ms);

        let query_bytes = match MessageBuilder::build_query("google.com", &RecordType::A) {
            Ok(b) => b,
            Err(e) => {
                self.mark_failed(&server_str, None, Some(e.to_string()));
                return;
            }
        };

        let dns_transport = match transport::create_transport(&protocol) {
            Ok(t) => t,
            Err(e) => {
                self.mark_failed(&server_str, None, Some(e.to_string()));
                return;
            }
        };

        let result = tokio::time::timeout(
            timeout_duration,
            dns_transport.send(&query_bytes, timeout_duration),
        )
        .await;
        let latency_ms = start.elapsed().as_millis() as u64;

        match result {
            Err(_) => {
                warn!(server = %server_str, "Health check: TIMEOUT");
                self.mark_failed(
                    &server_str,
                    None,
                    Some(format!("Timeout after {}ms", timeout_ms)),
                );
            }
            Ok(Err(e)) => {
                warn!(server = %server_str, error = %e, "Health check: FAILED");
                self.mark_failed(&server_str, Some(latency_ms), Some(e.to_string()));
            }
            Ok(Ok(resp)) => match ResponseParser::parse(&resp.bytes) {
                Ok(dns) if dns.is_server_error() => {
                    self.mark_failed(
                        &server_str,
                        Some(latency_ms),
                        Some(ResponseParser::rcode_to_status(dns.rcode).to_string()),
                    );
                }
                Ok(_) => {
                    debug!(server = %server_str, latency_ms, "Health check: OK");
                    self.mark_healthy(&server_str, latency_ms);
                }
                Err(e) => {
                    self.mark_failed(&server_str, Some(latency_ms), Some(e.to_string()));
                }
            },
        }
    }

    fn mark_healthy(&self, server: &str, latency_ms: u64) {
        let mut entry = self.health_map.entry(server.to_string()).or_default();
        entry.consecutive_failures = 0;
        entry.consecutive_successes += 1;
        entry.last_check_latency_ms = Some(latency_ms);
        entry.last_error = None;
        if entry.consecutive_successes >= self.success_threshold {
            if entry.status != ServerStatus::Healthy {
                info!(server = %server, latency_ms, "Server marked HEALTHY");
            }
            entry.status = ServerStatus::Healthy;
        }
    }

    fn mark_failed(&self, server: &str, latency_ms: Option<u64>, error: Option<String>) {
        let mut entry = self.health_map.entry(server.to_string()).or_default();
        entry.consecutive_successes = 0;
        entry.consecutive_failures += 1;
        entry.last_check_latency_ms = latency_ms;
        entry.last_error = error;
        if entry.consecutive_failures >= self.failure_threshold {
            if entry.status != ServerStatus::Unhealthy {
                warn!(server = %server, "Server marked UNHEALTHY");
            }
            entry.status = ServerStatus::Unhealthy;
        }
    }

    pub fn is_healthy(&self, protocol: &DnsProtocol) -> bool {
        let server_str = protocol.to_string();
        self.health_map
            .get(&server_str)
            .map(|h| h.status == ServerStatus::Healthy)
            .unwrap_or(true)
    }

    pub fn get_healthy_protocols(&self, protocols: &[DnsProtocol]) -> Vec<DnsProtocol> {
        protocols
            .iter()
            .filter(|p| self.is_healthy(p))
            .cloned()
            .collect()
    }

    pub fn get_status(&self, protocol: &DnsProtocol) -> ServerStatus {
        let server_str = protocol.to_string();
        self.health_map
            .get(&server_str)
            .map(|h| h.status)
            .unwrap_or(ServerStatus::Unknown)
    }

    pub fn get_health_info(&self, protocol: &DnsProtocol) -> Option<ServerHealth> {
        let server_str = protocol.to_string();
        self.health_map.get(&server_str).map(|h| h.clone())
    }
}
