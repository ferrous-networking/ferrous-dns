use super::udp_pool::UdpSocketPool;
use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, UpstreamAddr};
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::debug;

static DEFAULT_UDP_POOL: LazyLock<Arc<UdpSocketPool>> =
    LazyLock::new(|| Arc::new(UdpSocketPool::new(4, 64)));

pub fn validate_response_id(
    query_bytes: &[u8],
    response_bytes: &[u8],
    server: SocketAddr,
) -> Result<(), DomainError> {
    if query_bytes.len() < 2 || response_bytes.len() < 2 {
        return Err(DomainError::IoError(format!(
            "DNS response from {} is too short to contain a message ID",
            server
        )));
    }
    let query_id = u16::from_be_bytes([query_bytes[0], query_bytes[1]]);
    let response_id = u16::from_be_bytes([response_bytes[0], response_bytes[1]]);
    if query_id != response_id {
        return Err(DomainError::IoError(format!(
            "DNS message ID mismatch from {}: expected {}, got {}",
            server, query_id, response_id
        )));
    }
    Ok(())
}

fn validate_response_source(from: SocketAddr, expected: SocketAddr) -> Result<(), DomainError> {
    if from.ip() != expected.ip() {
        return Err(DomainError::IoError(format!(
            "UDP response from unexpected source: expected {}, got {}",
            expected.ip(),
            from.ip()
        )));
    }
    Ok(())
}

const MAX_UDP_RESPONSE_SIZE: usize = 4096;

/// Receive datagrams on `socket` until one arrives from the expected server
/// with the matching DNS message ID, or `timeout` elapses.
///
/// A pooled UDP socket is reused across queries, so it can still hold a late
/// response from a *previous* query, and an off-path attacker can inject
/// spoofed datagrams. A datagram from the wrong source or with a non-matching
/// message ID is therefore not our answer — it is drained and we keep waiting,
/// rather than failing the in-flight query. This keeps response/request
/// matching correct under socket reuse (the DNSSEC chain walk fires many
/// concurrent DS/DNSKEY queries) while preserving the anti-spoofing checks.
async fn recv_matching(
    socket: &UdpSocket,
    query_bytes: &[u8],
    server_addr: SocketAddr,
    timeout: Duration,
) -> Result<bytes::Bytes, DomainError> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut recv_buf = [0u8; MAX_UDP_RESPONSE_SIZE];

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(DomainError::IoError(format!(
                "Timeout waiting for UDP response from {}",
                server_addr
            )));
        }

        let (bytes_received, from_addr) =
            match tokio::time::timeout(remaining, socket.recv_from(&mut recv_buf)).await {
                Err(_) => {
                    return Err(DomainError::IoError(format!(
                        "Timeout waiting for UDP response from {}",
                        server_addr
                    )))
                }
                Ok(Err(e)) => {
                    return Err(DomainError::IoError(format!(
                        "Failed to receive UDP response from {}: {}",
                        server_addr, e
                    )))
                }
                Ok(Ok(v)) => v,
            };

        if validate_response_source(from_addr, server_addr).is_err() {
            debug!(
                server = %server_addr,
                actual = %from_addr.ip(),
                "Draining UDP datagram from unexpected source (anti-spoofing)"
            );
            continue;
        }
        if validate_response_id(query_bytes, &recv_buf[..bytes_received], server_addr).is_err() {
            debug!(
                server = %server_addr,
                "Draining stale/duplicate UDP datagram (message ID mismatch)"
            );
            continue;
        }

        return Ok(bytes::Bytes::copy_from_slice(&recv_buf[..bytes_received]));
    }
}

pub struct UdpTransport {
    upstream_addr: UpstreamAddr,
    pool: Option<Arc<UdpSocketPool>>,
}

impl UdpTransport {
    pub fn new(upstream_addr: UpstreamAddr) -> Self {
        Self {
            upstream_addr,
            pool: Some(Arc::clone(&DEFAULT_UDP_POOL)),
        }
    }

    pub fn with_pool(upstream_addr: UpstreamAddr, pool: Arc<UdpSocketPool>) -> Self {
        Self {
            upstream_addr,
            pool: Some(pool),
        }
    }

    fn resolved_addr(&self) -> Result<SocketAddr, DomainError> {
        self.upstream_addr.socket_addr().ok_or_else(|| {
            DomainError::IoError(format!(
                "UDP transport requires resolved address, got: {}",
                self.upstream_addr
            ))
        })
    }

    async fn send_with_pool(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        let server_addr = self.resolved_addr()?;

        if let Some(ref pool) = self.pool {
            let mut pooled = pool.acquire(server_addr).await.map_err(|e| {
                DomainError::IoError(format!("Failed to acquire UDP socket: {}", e))
            })?;

            let socket = pooled.socket();

            let bytes_sent =
                tokio::time::timeout(timeout, socket.send_to(message_bytes, server_addr))
                    .await
                    .map_err(|_| {
                        DomainError::IoError(format!(
                            "Timeout sending UDP query to {}",
                            server_addr
                        ))
                    })?
                    .map_err(|e| {
                        DomainError::IoError(format!(
                            "Failed to send UDP query to {}: {}",
                            server_addr, e
                        ))
                    })?;

            debug!(
                server = %server_addr,
                bytes_sent = bytes_sent,
                pooled = true,
                "UDP query sent"
            );

            // On any failure (incl. timeout) the socket may still have our
            // response in flight, so poison it rather than returning it to the
            // pool where it would corrupt the next query.
            let bytes = match recv_matching(socket, message_bytes, server_addr, timeout).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    pooled.poison();
                    return Err(e);
                }
            };

            debug!(
                server = %server_addr,
                bytes_received = bytes.len(),
                pooled = true,
                "UDP response received"
            );

            Ok(TransportResponse {
                bytes,
                protocol_used: "UDP",
            })
        } else {
            self.send_without_pool(message_bytes, timeout).await
        }
    }

    async fn send_without_pool(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        let server_addr = self.resolved_addr()?;

        let bind_addr: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| DomainError::IoError(format!("Failed to bind UDP socket: {}", e)))?;

        let bytes_sent = tokio::time::timeout(timeout, socket.send_to(message_bytes, server_addr))
            .await
            .map_err(|_| {
                DomainError::IoError(format!("Timeout sending UDP query to {}", server_addr))
            })?
            .map_err(|e| {
                DomainError::IoError(format!(
                    "Failed to send UDP query to {}: {}",
                    server_addr, e
                ))
            })?;

        debug!(
            server = %server_addr,
            bytes_sent = bytes_sent,
            pooled = false,
            "UDP query sent"
        );

        let bytes = recv_matching(&socket, message_bytes, server_addr, timeout).await?;

        debug!(
            server = %server_addr,
            bytes_received = bytes.len(),
            pooled = false,
            "UDP response received"
        );

        Ok(TransportResponse {
            bytes,
            protocol_used: "UDP",
        })
    }
}

#[async_trait]
impl DnsTransport for UdpTransport {
    async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        self.send_with_pool(message_bytes, timeout).await
    }

    fn protocol_name(&self) -> &'static str {
        "UDP"
    }
}
