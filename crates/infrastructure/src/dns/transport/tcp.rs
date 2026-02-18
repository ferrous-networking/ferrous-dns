use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

const MAX_TCP_MESSAGE_SIZE: usize = 65535;

pub struct TcpTransport {
    server_addr: SocketAddr,
}

impl TcpTransport {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self { server_addr }
    }
}

#[async_trait]
impl DnsTransport for TcpTransport {
    async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(self.server_addr))
            .await
            .map_err(|_| {
                DomainError::InvalidDomainName(format!(
                    "Timeout connecting to TCP server {}",
                    self.server_addr
                ))
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Connection refused by TCP server {}: {}",
                    self.server_addr, e
                ))
            })?;

        let length = message_bytes.len() as u16;
        let length_bytes = length.to_be_bytes();

        tokio::time::timeout(timeout, async {
            stream.write_all(&length_bytes).await?;
            stream.write_all(message_bytes).await?;
            stream.flush().await
        })
        .await
        .map_err(|_| {
            DomainError::InvalidDomainName(format!(
                "Timeout sending TCP query to {}",
                self.server_addr
            ))
        })?
        .map_err(|e| {
            DomainError::InvalidDomainName(format!(
                "Failed to send TCP query to {}: {}",
                self.server_addr, e
            ))
        })?;

        debug!(
            server = %self.server_addr,
            message_len = message_bytes.len(),
            "TCP query sent"
        );

        let response_bytes = tokio::time::timeout(timeout, async {
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await.map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Failed to read TCP response length from {}: {}",
                    self.server_addr, e
                ))
            })?;

            let response_len = u16::from_be_bytes(len_buf) as usize;

            if response_len > MAX_TCP_MESSAGE_SIZE {
                return Err(DomainError::InvalidDomainName(format!(
                    "TCP response too large: {} bytes (max {})",
                    response_len, MAX_TCP_MESSAGE_SIZE
                )));
            }

            let mut response = vec![0u8; response_len];
            stream.read_exact(&mut response).await.map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Failed to read TCP response from {}: {}",
                    self.server_addr, e
                ))
            })?;

            Ok(response)
        })
        .await
        .map_err(|_| {
            DomainError::InvalidDomainName(format!(
                "Timeout waiting for TCP response from {}",
                self.server_addr
            ))
        })??;

        debug!(
            server = %self.server_addr,
            response_len = response_bytes.len(),
            "TCP response received"
        );

        Ok(TransportResponse {
            bytes: response_bytes,
            protocol_used: "TCP",
        })
    }

    fn protocol_name(&self) -> &'static str {
        "TCP"
    }
}

pub(crate) async fn send_with_length_prefix<S>(
    stream: &mut S,
    message_bytes: &[u8],
) -> Result<(), DomainError>
where
    S: AsyncWriteExt + Unpin,
{
    let length = message_bytes.len() as u16;
    let length_bytes = length.to_be_bytes();

    stream.write_all(&length_bytes).await.map_err(|e| {
        DomainError::InvalidDomainName(format!("Failed to write length prefix: {}", e))
    })?;
    stream.write_all(message_bytes).await.map_err(|e| {
        DomainError::InvalidDomainName(format!("Failed to write DNS message: {}", e))
    })?;
    stream
        .flush()
        .await
        .map_err(|e| DomainError::InvalidDomainName(format!("Failed to flush stream: {}", e)))?;

    Ok(())
}

pub(crate) async fn read_with_length_prefix<S>(stream: &mut S) -> Result<Vec<u8>, DomainError>
where
    S: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await.map_err(|e| {
        DomainError::InvalidDomainName(format!("Failed to read response length: {}", e))
    })?;

    let response_len = u16::from_be_bytes(len_buf) as usize;

    if response_len > MAX_TCP_MESSAGE_SIZE {
        return Err(DomainError::InvalidDomainName(format!(
            "Response too large: {} bytes (max {})",
            response_len, MAX_TCP_MESSAGE_SIZE
        )));
    }

    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response).await.map_err(|e| {
        DomainError::InvalidDomainName(format!("Failed to read response body: {}", e))
    })?;

    Ok(response)
}
