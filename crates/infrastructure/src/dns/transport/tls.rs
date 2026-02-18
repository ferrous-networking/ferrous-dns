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

const MAX_IDLE_PER_HOST: usize = 2;

static SHARED_TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    Arc::new(config)
});

type TlsConnection = TlsStream<TcpStream>;
type PoolKey = (SocketAddr, String);
type TlsConnectionPool = DashMap<PoolKey, Vec<TlsConnection>>;

static TLS_POOL: LazyLock<TlsConnectionPool> = LazyLock::new(TlsConnectionPool::new);

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

    fn take_pooled(&self) -> Option<TlsStream<TcpStream>> {
        let key = (self.server_addr, self.hostname.clone());
        let mut entry = TLS_POOL.get_mut(&key)?;
        entry.pop()
    }

    fn return_to_pool(&self, stream: TlsStream<TcpStream>) {
        let key = (self.server_addr, self.hostname.clone());
        let mut entry = TLS_POOL.entry(key).or_default();
        if entry.len() < MAX_IDLE_PER_HOST {
            entry.push(stream);
        }
        
    }

    async fn connect_new(&self, timeout: Duration) -> Result<TlsStream<TcpStream>, DomainError> {
        let connector = tokio_rustls::TlsConnector::from(SHARED_TLS_CONFIG.clone());

        let server_name = ServerName::try_from(self.hostname.clone()).map_err(|e| {
            DomainError::InvalidDomainName(format!(
                "Invalid TLS hostname '{}': {}",
                self.hostname, e
            ))
        })?;

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
                    
                    debug!(server = %self.server_addr, "Pooled TLS connection stale, reconnecting");
                }
            }
        }

        let mut stream = self.connect_new(timeout).await?;

        let response_bytes = self
            .send_on_stream(&mut stream, message_bytes, timeout)
            .await?;

        debug!(
            server = %self.server_addr,
            response_len = response_bytes.len(),
            "TLS response received"
        );

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
