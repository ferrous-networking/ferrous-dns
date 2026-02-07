//! TLS Transport for DNS queries — DNS-over-TLS (RFC 7858)
//!
//! Optimized with:
//! - Static shared `ClientConfig` (built once, reused across all queries)
//! - TLS session resumption via rustls session cache (avoids full handshake)
//! - Connection pool: idle TLS connections are cached per (addr, hostname)
//!   and reused for subsequent queries, amortizing the handshake cost.
//!
//! Performance: full handshake ~40ms → reused connection ~1ms

use super::tcp::{read_with_length_prefix, send_with_length_prefix};
use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use dashmap::DashMap;
use ferrous_dns_domain::DomainError;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;
use tracing::debug;

/// Maximum idle connections per (addr, hostname) pair.
const MAX_IDLE_PER_HOST: usize = 2;

/// Shared TLS config — built once, reused for all DoT queries.
/// Enables TLS session resumption (session tickets) automatically.
static SHARED_TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(config)
});

/// Global connection pool for TLS connections, keyed by (addr, hostname).
/// Idle connections are reused to avoid repeated TCP+TLS handshakes.
static TLS_POOL: LazyLock<DashMap<(SocketAddr, String), Vec<TlsStream<TcpStream>>>> =
    LazyLock::new(DashMap::new);

/// DNS-over-TLS transport (RFC 7858)
pub struct TlsTransport {
    server_addr: SocketAddr,
    hostname: String,
}

impl TlsTransport {
    pub fn new(server_addr: SocketAddr, hostname: String) -> Self {
        Self {
            server_addr,
            hostname,
        }
    }

    /// Try to get an idle connection from the pool.
    fn take_pooled(&self) -> Option<TlsStream<TcpStream>> {
        let key = (self.server_addr, self.hostname.clone());
        let mut entry = TLS_POOL.get_mut(&key)?;
        entry.pop()
    }

    /// Return a connection to the pool for reuse.
    fn return_to_pool(&self, stream: TlsStream<TcpStream>) {
        let key = (self.server_addr, self.hostname.clone());
        let mut entry = TLS_POOL.entry(key).or_default();
        if entry.len() < MAX_IDLE_PER_HOST {
            entry.push(stream);
        }
        // If pool is full, connection is simply dropped (closed).
    }

    /// Establish a new TLS connection (TCP connect + TLS handshake).
    async fn connect_new(&self, timeout: Duration) -> Result<TlsStream<TcpStream>, DomainError> {
        let connector = tokio_rustls::TlsConnector::from(SHARED_TLS_CONFIG.clone());

        let server_name = ServerName::try_from(self.hostname.clone()).map_err(|e| {
            DomainError::InvalidDomainName(format!(
                "Invalid TLS hostname '{}': {}",
                self.hostname, e
            ))
        })?;

        // TCP connect
        let tcp_stream = tokio::time::timeout(timeout, TcpStream::connect(self.server_addr))
            .await
            .map_err(|_| {
                DomainError::InvalidDomainName(format!(
                    "Timeout connecting to TLS server {}",
                    self.server_addr
                ))
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Connection refused by TLS server {}: {}",
                    self.server_addr, e
                ))
            })?;

        // TLS handshake (session resumption happens automatically via rustls session cache)
        let tls_stream = tokio::time::timeout(timeout, connector.connect(server_name, tcp_stream))
            .await
            .map_err(|_| {
                DomainError::InvalidDomainName(format!(
                    "Timeout during TLS handshake with {}",
                    self.server_addr
                ))
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "TLS handshake failed with {}: {}",
                    self.server_addr, e
                ))
            })?;

        debug!(server = %self.server_addr, hostname = %self.hostname, "TLS connection established");
        Ok(tls_stream)
    }

    /// Send a query over an existing TLS stream. Returns the stream on success
    /// (for pooling) or None on failure.
    async fn send_on_stream(
        &self,
        stream: &mut TlsStream<TcpStream>,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Vec<u8>, DomainError> {
        tokio::time::timeout(timeout, send_with_length_prefix(stream, message_bytes))
            .await
            .map_err(|_| {
                DomainError::InvalidDomainName(format!(
                    "Timeout sending TLS query to {}",
                    self.server_addr
                ))
            })??;

        let response_bytes = tokio::time::timeout(timeout, read_with_length_prefix(stream))
            .await
            .map_err(|_| {
                DomainError::InvalidDomainName(format!(
                    "Timeout waiting for TLS response from {}",
                    self.server_addr
                ))
            })??;

        Ok(response_bytes)
    }
}

#[async_trait]
impl DnsTransport for TlsTransport {
    async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        // Try reusing a pooled connection first
        if let Some(mut stream) = self.take_pooled() {
            match self
                .send_on_stream(&mut stream, message_bytes, timeout)
                .await
            {
                Ok(response_bytes) => {
                    debug!(server = %self.server_addr, "TLS query via pooled connection");
                    self.return_to_pool(stream);
                    return Ok(TransportResponse {
                        bytes: response_bytes,
                        protocol_used: "TLS",
                    });
                }
                Err(_) => {
                    // Pooled connection was stale — fall through to new connection
                    debug!(server = %self.server_addr, "Pooled TLS connection stale, reconnecting");
                }
            }
        }

        // Establish new connection
        let mut stream = self.connect_new(timeout).await?;

        let response_bytes = self
            .send_on_stream(&mut stream, message_bytes, timeout)
            .await?;

        debug!(
            server = %self.server_addr,
            response_len = response_bytes.len(),
            "TLS response received"
        );

        // Return connection to pool for reuse
        self.return_to_pool(stream);

        Ok(TransportResponse {
            bytes: response_bytes,
            protocol_used: "TLS",
        })
    }

    fn protocol_name(&self) -> &'static str {
        "TLS"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_transport_creation() {
        let addr: SocketAddr = "1.1.1.1:853".parse().unwrap();
        let transport = TlsTransport::new(addr, "cloudflare-dns.com".to_string());
        assert_eq!(transport.server_addr, addr);
        assert_eq!(transport.hostname, "cloudflare-dns.com");
        assert_eq!(transport.protocol_name(), "TLS");
    }

    #[test]
    fn test_shared_tls_config() {
        // Verify the static config builds successfully
        let _config = &*SHARED_TLS_CONFIG;
    }
}
