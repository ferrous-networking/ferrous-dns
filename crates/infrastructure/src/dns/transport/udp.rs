//! UDP Transport for DNS queries (RFC 1035 §4.2.1)
//!
//! Standard DNS transport. Messages are sent as-is (no framing).
//! Limited to 512 bytes without EDNS(0), or up to 4096 bytes with EDNS(0).
//! If the response has the TC (truncated) bit set, the caller should retry via TCP.

use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

/// Maximum UDP DNS response size with EDNS(0)
const MAX_UDP_RESPONSE_SIZE: usize = 4096;

/// DNS over UDP transport
pub struct UdpTransport {
    server_addr: SocketAddr,
}

impl UdpTransport {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self { server_addr }
    }
}

#[async_trait]
impl DnsTransport for UdpTransport {
    async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        // Bind to ephemeral port (0 = OS assigns)
        let bind_addr: SocketAddr = if self.server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to bind UDP socket: {}", e))
        })?;

        // Send query
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
            "UDP query sent"
        );

        // Receive response
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

        // Validate response came from expected server
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
            "UDP response received"
        );

        Ok(TransportResponse {
            bytes: recv_buf,
            protocol_used: "UDP",
        })
    }

    fn protocol_name(&self) -> &'static str {
        "UDP"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_transport_creation() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let transport = UdpTransport::new(addr);
        assert_eq!(transport.server_addr, addr);
        assert_eq!(transport.protocol_name(), "UDP");
    }

    #[test]
    fn test_udp_transport_ipv6() {
        let addr: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
        let transport = UdpTransport::new(addr);
        assert_eq!(transport.server_addr, addr);
    }
}
