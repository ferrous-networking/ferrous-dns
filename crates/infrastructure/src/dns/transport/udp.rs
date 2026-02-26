use super::udp_pool::UdpSocketPool;
use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use ferrous_dns_domain::{DomainError, UpstreamAddr};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

pub fn validate_response_id(
    query_bytes: &[u8],
    response_bytes: &[u8],
    server: SocketAddr,
) -> Result<(), DomainError> {
    if query_bytes.len() < 2 || response_bytes.len() < 2 {
        return Err(DomainError::InvalidDomainName(format!(
            "DNS response from {} is too short to contain a message ID",
            server
        )));
    }
    let query_id = u16::from_be_bytes([query_bytes[0], query_bytes[1]]);
    let response_id = u16::from_be_bytes([response_bytes[0], response_bytes[1]]);
    if query_id != response_id {
        warn!(
            server = %server,
            query_id,
            response_id,
            "DNS message ID mismatch — discarding response to prevent spoofing"
        );
        return Err(DomainError::InvalidDomainName(format!(
            "DNS message ID mismatch from {}: expected {}, got {}",
            server, query_id, response_id
        )));
    }
    Ok(())
}

fn validate_response_source(from: SocketAddr, expected: SocketAddr) -> Result<(), DomainError> {
    if from.ip() != expected.ip() {
        warn!(
            expected = %expected.ip(),
            actual = %from.ip(),
            "Rejecting UDP response from unexpected source (anti-spoofing)"
        );
        return Err(DomainError::InvalidDomainName(format!(
            "UDP response from unexpected source: expected {}, got {}",
            expected.ip(),
            from.ip()
        )));
    }
    Ok(())
}

const MAX_UDP_RESPONSE_SIZE: usize = 4096;

pub struct UdpTransport {
    upstream_addr: UpstreamAddr,
    pool: Option<Arc<UdpSocketPool>>,
}

impl UdpTransport {
    pub fn new(upstream_addr: UpstreamAddr) -> Self {
        Self {
            upstream_addr,
            pool: None,
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
            DomainError::InvalidDomainName(format!(
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
            let pooled = pool.acquire(server_addr).await.map_err(|e| {
                DomainError::InvalidDomainName(format!("Failed to acquire UDP socket: {}", e))
            })?;

            let socket = pooled.socket();

            let bytes_sent =
                tokio::time::timeout(timeout, socket.send_to(message_bytes, server_addr))
                    .await
                    .map_err(|_| {
                        DomainError::InvalidDomainName(format!(
                            "Timeout sending UDP query to {}",
                            server_addr
                        ))
                    })?
                    .map_err(|e| {
                        DomainError::InvalidDomainName(format!(
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

            let mut recv_buf = [0u8; MAX_UDP_RESPONSE_SIZE];

            let (bytes_received, from_addr) =
                tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf))
                    .await
                    .map_err(|_| {
                        DomainError::InvalidDomainName(format!(
                            "Timeout waiting for UDP response from {}",
                            server_addr
                        ))
                    })?
                    .map_err(|e| {
                        DomainError::InvalidDomainName(format!(
                            "Failed to receive UDP response from {}: {}",
                            server_addr, e
                        ))
                    })?;

            validate_response_source(from_addr, server_addr)?;
            validate_response_id(message_bytes, &recv_buf[..bytes_received], server_addr)?;

            debug!(
                server = %server_addr,
                bytes_received = bytes_received,
                pooled = true,
                "UDP response received"
            );

            Ok(TransportResponse {
                bytes: bytes::Bytes::copy_from_slice(&recv_buf[..bytes_received]),
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

        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to bind UDP socket: {}", e))
        })?;

        let bytes_sent = tokio::time::timeout(timeout, socket.send_to(message_bytes, server_addr))
            .await
            .map_err(|_| {
                DomainError::InvalidDomainName(format!(
                    "Timeout sending UDP query to {}",
                    server_addr
                ))
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
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

        let mut recv_buf = [0u8; MAX_UDP_RESPONSE_SIZE];

        let (bytes_received, from_addr) =
            tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf))
                .await
                .map_err(|_| {
                    DomainError::InvalidDomainName(format!(
                        "Timeout waiting for UDP response from {}",
                        server_addr
                    ))
                })?
                .map_err(|e| {
                    DomainError::InvalidDomainName(format!(
                        "Failed to receive UDP response from {}: {}",
                        server_addr, e
                    ))
                })?;

        validate_response_source(from_addr, server_addr)?;
        validate_response_id(message_bytes, &recv_buf[..bytes_received], server_addr)?;

        debug!(
            server = %server_addr,
            bytes_received = bytes_received,
            pooled = false,
            "UDP response received"
        );

        Ok(TransportResponse {
            bytes: bytes::Bytes::copy_from_slice(&recv_buf[..bytes_received]),
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
