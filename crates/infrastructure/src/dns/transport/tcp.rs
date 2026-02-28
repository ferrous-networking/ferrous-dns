use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use dashmap::DashMap;
use ferrous_dns_domain::{DomainError, UpstreamAddr};
use std::net::SocketAddr;
use std::sync::LazyLock;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

const MAX_TCP_MESSAGE_SIZE: usize = 65535;
const MAX_IDLE_TCP_PER_HOST: usize = 12;

type TcpConnectionPool = DashMap<UpstreamAddr, Vec<TcpStream>>;

static TCP_POOL: LazyLock<TcpConnectionPool> = LazyLock::new(TcpConnectionPool::new);

pub struct TcpTransport {
    upstream_addr: UpstreamAddr,
}

impl TcpTransport {
    pub fn new(upstream_addr: UpstreamAddr) -> Self {
        Self { upstream_addr }
    }

    fn resolved_addr(&self) -> Result<SocketAddr, DomainError> {
        self.upstream_addr.socket_addr().ok_or_else(|| {
            DomainError::IoError(format!(
                "TCP transport requires resolved address, got: {}",
                self.upstream_addr
            ))
        })
    }

    fn take_pooled(&self) -> Option<TcpStream> {
        TCP_POOL.get_mut(&self.upstream_addr)?.pop()
    }

    fn return_to_pool(&self, stream: TcpStream) {
        let mut entry = TCP_POOL.entry(self.upstream_addr.clone()).or_default();
        if entry.len() < MAX_IDLE_TCP_PER_HOST {
            entry.push(stream);
        }
    }

    async fn connect_new(&self, timeout: Duration) -> Result<TcpStream, DomainError> {
        let server_addr = self.resolved_addr()?;

        let stream = tokio::time::timeout(timeout, TcpStream::connect(server_addr))
            .await
            .map_err(|_| {
                DomainError::IoError(format!("Timeout connecting to TCP server {}", server_addr))
            })?
            .map_err(|e| {
                DomainError::IoError(format!(
                    "Connection refused by TCP server {}: {}",
                    server_addr, e
                ))
            })?;

        stream.set_nodelay(true).map_err(|e| {
            DomainError::IoError(format!(
                "Failed to set TCP_NODELAY on {}: {}",
                server_addr, e
            ))
        })?;

        let sock_ref = socket2::SockRef::from(&stream);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(15))
            .with_interval(Duration::from_secs(5));
        if let Err(e) = sock_ref.set_tcp_keepalive(&keepalive) {
            debug!(server = %server_addr, error = %e, "Failed to set TCP keepalive");
        }

        Ok(stream)
    }
}

#[async_trait]
impl DnsTransport for TcpTransport {
    async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        let server_addr = self.resolved_addr()?;

        let mut stream = match self.take_pooled() {
            Some(s) => s,
            None => self.connect_new(timeout).await?,
        };

        let send_result = tokio::time::timeout(timeout, async {
            send_with_length_prefix(&mut stream, message_bytes).await
        })
        .await;

        let mut stream = match send_result {
            Ok(Ok(())) => stream,
            _ => {
                let mut fresh = self.connect_new(timeout).await?;
                tokio::time::timeout(timeout, send_with_length_prefix(&mut fresh, message_bytes))
                    .await
                    .map_err(|_| {
                        DomainError::IoError(format!(
                            "Timeout sending TCP query to {}",
                            server_addr
                        ))
                    })?
                    .map_err(|e| {
                        DomainError::IoError(format!(
                            "Failed to send TCP query to {}: {}",
                            server_addr, e
                        ))
                    })?;
                fresh
            }
        };

        debug!(
            server = %server_addr,
            message_len = message_bytes.len(),
            "TCP query sent"
        );

        let response_bytes = tokio::time::timeout(timeout, async {
            read_with_length_prefix(&mut stream).await
        })
        .await
        .map_err(|_| {
            DomainError::IoError(format!(
                "Timeout waiting for TCP response from {}",
                server_addr
            ))
        })??;

        debug!(
            server = %server_addr,
            response_len = response_bytes.len(),
            "TCP response received"
        );

        self.return_to_pool(stream);

        Ok(TransportResponse {
            bytes: bytes::Bytes::from(response_bytes),
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

    stream
        .write_all(&length_bytes)
        .await
        .map_err(|e| DomainError::IoError(format!("Failed to write length prefix: {}", e)))?;
    stream
        .write_all(message_bytes)
        .await
        .map_err(|e| DomainError::IoError(format!("Failed to write DNS message: {}", e)))?;
    stream
        .flush()
        .await
        .map_err(|e| DomainError::IoError(format!("Failed to flush stream: {}", e)))?;

    Ok(())
}

pub(crate) async fn read_with_length_prefix<S>(stream: &mut S) -> Result<Vec<u8>, DomainError>
where
    S: AsyncReadExt + Unpin,
{
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| DomainError::IoError(format!("Failed to read response length: {}", e)))?;

    let response_len = u16::from_be_bytes(len_buf) as usize;

    if response_len > MAX_TCP_MESSAGE_SIZE {
        return Err(DomainError::IoError(format!(
            "Response too large: {} bytes (max {})",
            response_len, MAX_TCP_MESSAGE_SIZE
        )));
    }

    let mut response = vec![0u8; response_len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| DomainError::IoError(format!("Failed to read response body: {}", e)))?;

    Ok(response)
}
