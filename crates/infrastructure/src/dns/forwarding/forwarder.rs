use super::message_builder::MessageBuilder;
use super::response_parser::{DnsResponse, ResponseParser};
use ferrous_dns_domain::{DomainError, RecordType};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;

/// DNS Forwarder for sending queries to specific servers
pub struct DnsForwarder;

impl DnsForwarder {
    pub fn new() -> Self {
        Self
    }

    /// Query a specific DNS server
    pub async fn query(
        &self,
        server: &str,
        domain: &str,
        record_type: &RecordType,
        timeout_ms: u64,
    ) -> Result<DnsResponse, DomainError> {
        // Parse server address
        let server_addr: SocketAddr = server.parse().map_err(|e| {
            DomainError::InvalidDomainName(format!("Invalid server address: {}", e))
        })?;

        // Build DNS query using MessageBuilder
        let request_bytes = MessageBuilder::build_query(domain, record_type)?;

        // Send query via UDP
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Failed to bind socket: {}", e)))?;

        socket.connect(server_addr).await.map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to connect to server: {}", e))
        })?;

        socket
            .send(&request_bytes)
            .await
            .map_err(|e| DomainError::InvalidDomainName(format!("Failed to send query: {}", e)))?;

        // Receive response with timeout
        let mut response_buf = vec![0u8; 4096];
        let timeout = Duration::from_millis(timeout_ms);

        let len = tokio::time::timeout(timeout, socket.recv(&mut response_buf))
            .await
            .map_err(|_| DomainError::QueryTimeout)?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!("Failed to receive response: {}", e))
            })?;

        // Parse response using ResponseParser
        ResponseParser::parse(&response_buf[..len])
    }
}
