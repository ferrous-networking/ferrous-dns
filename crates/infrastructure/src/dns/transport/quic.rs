use super::tcp::{read_with_length_prefix, send_with_length_prefix};
use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use dashmap::DashMap;
use ferrous_dns_domain::{DomainError, UpstreamAddr};
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tracing::debug;

type PoolKey = (SocketAddr, String);

static SHARED_QUIC_CLIENT_CONFIG: LazyLock<quinn::ClientConfig> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"doq".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))
        .expect("valid QUIC TLS config");
    quinn::ClientConfig::new(Arc::new(quic_config))
});

static QUIC_ENDPOINT_V4: LazyLock<quinn::Endpoint> = LazyLock::new(|| {
    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("QUIC IPv4 client endpoint");
    endpoint.set_default_client_config(SHARED_QUIC_CLIENT_CONFIG.clone());
    endpoint
});

static QUIC_ENDPOINT_V6: LazyLock<quinn::Endpoint> = LazyLock::new(|| {
    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse().unwrap()).expect("QUIC IPv6 client endpoint");
    endpoint.set_default_client_config(SHARED_QUIC_CLIENT_CONFIG.clone());
    endpoint
});

fn quic_endpoint_for(addr: &SocketAddr) -> &'static quinn::Endpoint {
    if addr.is_ipv4() {
        &QUIC_ENDPOINT_V4
    } else {
        &QUIC_ENDPOINT_V6
    }
}

static QUIC_POOL: LazyLock<DashMap<PoolKey, quinn::Connection>> = LazyLock::new(DashMap::new);

pub struct QuicTransport {
    upstream_addr: UpstreamAddr,
    hostname: Arc<str>,
}

impl QuicTransport {
    pub fn new(upstream_addr: UpstreamAddr, hostname: Arc<str>) -> Self {
        Self {
            upstream_addr,
            hostname,
        }
    }

    fn resolved_addr(&self) -> Result<SocketAddr, DomainError> {
        self.upstream_addr.socket_addr().ok_or_else(|| {
            DomainError::InvalidDomainName(format!(
                "QUIC transport requires resolved address, got: {}",
                self.upstream_addr
            ))
        })
    }

    async fn get_or_connect(&self, timeout: Duration) -> Result<quinn::Connection, DomainError> {
        let server_addr = self.resolved_addr()?;
        let key = (server_addr, self.hostname.to_string());
        if let Some(conn) = QUIC_POOL.get(&key) {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
            drop(conn);
            QUIC_POOL.remove(&key);
        }
        let conn = self.connect_new(timeout).await?;
        QUIC_POOL.insert(key, conn.clone());
        Ok(conn)
    }

    async fn connect_new(&self, timeout: Duration) -> Result<quinn::Connection, DomainError> {
        let server_addr = self.resolved_addr()?;
        let endpoint = quic_endpoint_for(&server_addr);

        let connecting = endpoint
            .connect(server_addr, self.hostname.as_ref())
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Failed to initiate QUIC connection to {}: {}",
                    server_addr, e
                ))
            })?;

        tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: server_addr.to_string(),
            })?
            .map_err(|e| DomainError::TransportConnectionRefused {
                server: format!("{}({}): {}", self.hostname, server_addr, e),
            })
    }

    async fn send_on_stream(
        conn: &quinn::Connection,
        message_bytes: &[u8],
        timeout: Duration,
        server_addr: SocketAddr,
    ) -> Result<Vec<u8>, DomainError> {
        let (mut send_stream, mut recv_stream) = tokio::time::timeout(timeout, conn.open_bi())
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: server_addr.to_string(),
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Failed to open QUIC stream to {}: {}",
                    server_addr, e
                ))
            })?;

        tokio::time::timeout(
            timeout,
            send_with_length_prefix(&mut send_stream, message_bytes),
        )
        .await
        .map_err(|_| DomainError::TransportTimeout {
            server: server_addr.to_string(),
        })??;

        send_stream.finish().map_err(|e| {
            DomainError::IoError(format!(
                "Failed to finish QUIC send stream to {}: {}",
                server_addr, e
            ))
        })?;

        tokio::time::timeout(timeout, read_with_length_prefix(&mut recv_stream))
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: server_addr.to_string(),
            })?
    }
}

#[async_trait]
impl DnsTransport for QuicTransport {
    async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        let server_addr = self.resolved_addr()?;
        let conn = self.get_or_connect(timeout).await?;

        match Self::send_on_stream(&conn, message_bytes, timeout, server_addr).await {
            Ok(response_bytes) => {
                debug!(server = %server_addr, "QUIC query via pooled connection");
                return Ok(TransportResponse {
                    bytes: bytes::Bytes::from(response_bytes),
                    protocol_used: "QUIC",
                });
            }
            Err(_) => {
                QUIC_POOL.remove(&(server_addr, self.hostname.to_string()));
                debug!(server = %server_addr, "QUIC connection stale, reconnecting");
            }
        }

        let fresh_conn = self.connect_new(timeout).await?;
        QUIC_POOL.insert((server_addr, self.hostname.to_string()), fresh_conn.clone());

        let response_bytes =
            Self::send_on_stream(&fresh_conn, message_bytes, timeout, server_addr).await?;

        debug!(
            server = %server_addr,
            response_len = response_bytes.len(),
            "QUIC response received"
        );

        Ok(TransportResponse {
            bytes: bytes::Bytes::from(response_bytes),
            protocol_used: "QUIC",
        })
    }

    fn protocol_name(&self) -> &'static str {
        "QUIC"
    }
}
