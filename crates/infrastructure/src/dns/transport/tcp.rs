use super::require_resolved;
use bytes::{Buf, Bytes};
use ferrous_dns_domain::{DomainError, UpstreamAddr};
use std::net::SocketAddr;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout_at, Instant};
use tracing::debug;

const MAX_IDLE_TCP_PER_HOST: usize = 12;

/// Idle connections to one upstream, handed out most recently parked first.
pub(crate) struct IdlePool<S> {
    idle: Mutex<Vec<S>>,
    max: usize,
}

impl<S> IdlePool<S> {
    pub(crate) fn new(max: usize) -> Self {
        Self {
            idle: Mutex::new(Vec::new()),
            max,
        }
    }

    pub(crate) fn take(&self) -> Option<S> {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop()
    }

    pub(crate) fn park(&self, stream: S) {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < self.max {
            idle.push(stream);
        }
    }
}

pub struct TcpTransport {
    upstream_addr: UpstreamAddr,
    idle: IdlePool<TcpStream>,
}

impl TcpTransport {
    pub fn new(upstream_addr: UpstreamAddr) -> Self {
        Self {
            upstream_addr,
            idle: IdlePool::new(MAX_IDLE_TCP_PER_HOST),
        }
    }

    pub async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Bytes, DomainError> {
        let server_addr = require_resolved(&self.upstream_addr, "TCP")?;
        // One budget for the whole exchange, reconnect included.
        let deadline = Instant::now() + timeout;

        if let Some(mut stream) = self.idle.take() {
            match exchange_framed(&mut stream, message_bytes, deadline, server_addr, "TCP").await {
                Ok(response) => {
                    self.idle.park(stream);
                    return Ok(Bytes::from(response));
                }
                Err(e) if Instant::now() >= deadline => return Err(e),
                // Servers close idle connections (RFC 7766 §6.2.3), and the write
                // into a half-closed one still succeeds; only the read fails.
                Err(e) => {
                    debug!(server = %server_addr, error = %e, "Pooled TCP connection stale, reconnecting");
                }
            }
        }

        let mut stream = connect_tcp(server_addr, deadline, "TCP").await?;
        let response =
            exchange_framed(&mut stream, message_bytes, deadline, server_addr, "TCP").await?;
        debug!(
            server = %server_addr,
            response_len = response.len(),
            "TCP response received"
        );
        self.idle.park(stream);
        Ok(Bytes::from(response))
    }
}

/// Connects to `server` with `TCP_NODELAY`, so a query on a reused connection
/// does not wait for the ACK of the previous one, and keepalive.
pub(crate) async fn connect_tcp(
    server: SocketAddr,
    deadline: Instant,
    label: &str,
) -> Result<TcpStream, DomainError> {
    let stream = timeout_at(deadline, TcpStream::connect(server))
        .await
        .map_err(|_| {
            DomainError::IoError(format!("Timeout connecting to {label} server {server}"))
        })?
        .map_err(|e| {
            DomainError::IoError(format!("Could not connect to {label} server {server}: {e}"))
        })?;

    stream
        .set_nodelay(true)
        .map_err(|e| DomainError::IoError(format!("Failed to set TCP_NODELAY on {server}: {e}")))?;

    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(15))
        .with_interval(Duration::from_secs(5));
    if let Err(e) = socket2::SockRef::from(&stream).set_tcp_keepalive(&keepalive) {
        debug!(server = %server, error = %e, "Failed to set TCP keepalive");
    }

    Ok(stream)
}

/// Writes one length-prefixed query and reads the length-prefixed answer, both
/// before `deadline`.
pub(crate) async fn exchange_framed<S>(
    stream: &mut S,
    message_bytes: &[u8],
    deadline: Instant,
    server: SocketAddr,
    label: &str,
) -> Result<Vec<u8>, DomainError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout_at(deadline, send_with_length_prefix(stream, message_bytes))
        .await
        .map_err(|_| {
            DomainError::IoError(format!("Timeout sending {label} query to {server}"))
        })??;

    timeout_at(deadline, read_with_length_prefix(stream))
        .await
        .map_err(|_| {
            DomainError::IoError(format!(
                "Timeout waiting for {label} response from {server}"
            ))
        })?
}

pub(crate) async fn send_with_length_prefix<S>(
    stream: &mut S,
    message: impl Buf,
) -> Result<(), DomainError>
where
    S: AsyncWrite + Unpin,
{
    let length_bytes = (message.remaining() as u16).to_be_bytes();

    // One vectored write keeps the prefix and query in one segment or TLS record.
    stream
        .write_all_buf(&mut Buf::chain(&length_bytes[..], message))
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
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| DomainError::IoError(format!("Failed to read response length: {}", e)))?;

    let response_len = usize::from(u16::from_be_bytes(len_buf));
    let mut response = vec![0u8; response_len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| DomainError::IoError(format!("Failed to read response body: {}", e)))?;

    Ok(response)
}
