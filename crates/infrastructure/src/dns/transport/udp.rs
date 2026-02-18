use super::udp_pool::UdpSocketPool;
use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

const MAX_UDP_RESPONSE_SIZE: usize = 4096;

pub struct UdpTransport {
    server_addr: SocketAddr,
    pool: Option<Arc<UdpSocketPool>>,
}

impl UdpTransport {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            pool: None,
        }
    }

    pub fn with_pool(server_addr: SocketAddr, pool: Arc<UdpSocketPool>) -> Self {
        Self {
            server_addr,
            pool: Some(pool),
        }
    }

    async fn send_with_pool(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        if let Some(ref pool) = self.pool {
            let pooled = pool.acquire(self.server_addr).await.map_err(|e| {
                DomainError::InvalidDomainName(format!("Failed to acquire UDP socket: {}", e))
            })?;

            let socket = pooled.socket();

            let bytes_sent =
                tokio::time::timeout(timeout, socket.send_to(message_bytes, self.server_addr))
                    .await
                    .map_err(|_| {
                        DomainError::InvalidDomainName(format!(
                            "Timeout sending UDP query to {}",
                            self.server_addr
                        ))
                    })?
                    .map_err(|e| {
                        DomainError::InvalidDomainName(format!(
                            "Failed to send UDP query to {}: {}",
                            self.server_addr, e
                        ))
                    })?;

            debug!(
                server = %self.server_addr,
                bytes_sent = bytes_sent,
                pooled = true,
                "UDP query sent"
            );

            let mut recv_buf = vec![0u8; MAX_UDP_RESPONSE_SIZE];

            let (bytes_received, from_addr) =
                tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf))
                    .await
                    .map_err(|_| {
                        DomainError::InvalidDomainName(format!(
                            "Timeout waiting for UDP response from {}",
                            self.server_addr
                        ))
                    })?
                    .map_err(|e| {
                        DomainError::InvalidDomainName(format!(
                            "Failed to receive UDP response from {}: {}",
                            self.server_addr, e
                        ))
                    })?;

            if from_addr.ip() != self.server_addr.ip() {
                warn!(
                    expected = %self.server_addr,
                    received_from = %from_addr,
                    "UDP response from unexpected source"
                );
            }

            recv_buf.truncate(bytes_received);

            debug!(
                server = %self.server_addr,
                bytes_received = bytes_received,
                pooled = true,
                "UDP response received"
            );

            Ok(TransportResponse {
                bytes: recv_buf,
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
        let bind_addr: SocketAddr = if self.server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to bind UDP socket: {}", e))
        })?;

        let bytes_sent =
            tokio::time::timeout(timeout, socket.send_to(message_bytes, self.server_addr))
                .await
                .map_err(|_| {
                    DomainError::InvalidDomainName(format!(
                        "Timeout sending UDP query to {}",
                        self.server_addr
                    ))
                })?
                .map_err(|e| {
                    DomainError::InvalidDomainName(format!(
                        "Failed to send UDP query to {}: {}",
                        self.server_addr, e
                    ))
                })?;

        debug!(
            server = %self.server_addr,
            bytes_sent = bytes_sent,
            pooled = false,
            "UDP query sent"
        );

        let mut recv_buf = vec![0u8; MAX_UDP_RESPONSE_SIZE];

        let (bytes_received, from_addr) =
            tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf))
                .await
                .map_err(|_| {
                    DomainError::InvalidDomainName(format!(
                        "Timeout waiting for UDP response from {}",
                        self.server_addr
                    ))
                })?
                .map_err(|e| {
                    DomainError::InvalidDomainName(format!(
                        "Failed to receive UDP response from {}: {}",
                        self.server_addr, e
                    ))
                })?;

        if from_addr.ip() != self.server_addr.ip() {
            warn!(
                expected = %self.server_addr,
                received_from = %from_addr,
                "UDP response from unexpected source"
            );
        }

        recv_buf.truncate(bytes_received);

        debug!(
            server = %self.server_addr,
            bytes_received = bytes_received,
            pooled = false,
            "UDP response received"
        );

        Ok(TransportResponse {
            bytes: recv_buf,
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
