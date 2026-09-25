use crate::dns::forwarding::{DnsForwarder, HardeningOpts};
use ferrous_dns_domain::{DomainError, RecordType};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::debug;

/// How long `local_dns_server` gets to answer before the system resolver is asked.
const LOCAL_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);

/// Looks up the hostnames in upstream URLs: through `local_dns_server` (the LAN
/// router) first when one is set, then the system resolver. The router comes
/// first because a machine that resolves through Ferrous DNS itself cannot look
/// its upstreams up any other way: at startup nothing answers yet, and later
/// Ferrous DNS has no resolved upstream to ask.
pub struct UpstreamHostResolver {
    local_dns_server: Option<SocketAddr>,
    forwarder: DnsForwarder,
}

impl UpstreamHostResolver {
    /// `hardening` should be the upstream pools', as for every query to the router.
    pub fn new(local_dns_server: Option<SocketAddr>, hardening: HardeningOpts) -> Self {
        Self {
            local_dns_server,
            forwarder: DnsForwarder::new(hardening),
        }
    }

    /// Only the system resolver, as when `local_dns_server` is unset.
    pub fn system() -> Self {
        Self::new(None, HardeningOpts::default())
    }

    pub async fn resolve_all(
        &self,
        hostname: &str,
        port: u16,
        timeout: Duration,
    ) -> Result<Vec<SocketAddr>, DomainError> {
        if let Some(server) = self.local_dns_server {
            match self.resolve_through(server, hostname, port).await {
                Ok(addrs) => return Ok(addrs),
                Err(e) => debug!(
                    hostname,
                    %server,
                    error = %e,
                    "Local DNS server did not resolve the upstream hostname; asking the system resolver"
                ),
            }
        }
        resolve_all(hostname, port, timeout).await
    }

    async fn resolve_through(
        &self,
        server: SocketAddr,
        hostname: &str,
        port: u16,
    ) -> Result<Vec<SocketAddr>, DomainError> {
        let timeout_ms = LOCAL_LOOKUP_TIMEOUT.as_millis() as u64;
        let (a, aaaa) = tokio::join!(
            self.forwarder
                .query(server, hostname, &RecordType::A, timeout_ms),
            self.forwarder
                .query(server, hostname, &RecordType::AAAA, timeout_ms),
        );
        let responses = match (a, aaaa) {
            (Err(e), Err(_)) => return Err(e),
            (a, aaaa) => [a, aaaa],
        };
        let addrs: Vec<SocketAddr> = responses
            .into_iter()
            .flatten()
            .flat_map(|response| response.addresses)
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        if addrs.is_empty() {
            return Err(DomainError::IoError(format!(
                "No addresses found for {hostname}:{port} at {server}"
            )));
        }
        Ok(addrs)
    }
}

/// Resolves a hostname to all its IP addresses (IPv4 + IPv6).
pub async fn resolve_all(
    hostname: &str,
    port: u16,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, DomainError> {
    let target = || format!("{hostname}:{port}");

    let addrs: Vec<SocketAddr> =
        tokio::time::timeout(timeout, tokio::net::lookup_host((hostname, port)))
            .await
            .map_err(|_| DomainError::TransportTimeout { server: target() })?
            .map_err(|e| {
                DomainError::IoError(format!("DNS resolution failed for {}: {}", target(), e))
            })?
            .collect();

    if addrs.is_empty() {
        return Err(DomainError::IoError(format!(
            "No addresses found for {}",
            target()
        )));
    }

    Ok(addrs)
}
