use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use dashmap::DashMap;
use ferrous_dns_domain::DomainError;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tracing::debug;

type PoolKey = String;
type H3SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

static H3_QUIC_CLIENT_CONFIG: LazyLock<quinn::ClientConfig> = LazyLock::new(|| {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls_config))
        .expect("valid QUIC TLS config for H3");
    quinn::ClientConfig::new(Arc::new(quic_config))
});

static H3_QUIC_ENDPOINT: LazyLock<quinn::Endpoint> = LazyLock::new(|| {
    let mut endpoint =
        quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).expect("H3 QUIC client endpoint");
    endpoint.set_default_client_config(H3_QUIC_CLIENT_CONFIG.clone());
    endpoint
});

static H3_POOL: LazyLock<DashMap<PoolKey, H3SendRequest>> = LazyLock::new(DashMap::new);

pub struct H3Transport {
    https_url: String,
    hostname: String,
    port: u16,
    pool_key: String,
}

impl H3Transport {
    pub fn new(h3_url: String) -> Self {
        let without_scheme = h3_url.strip_prefix("h3://").unwrap_or(&h3_url);
        let host_part = without_scheme.split('/').next().unwrap_or(without_scheme);
        let (hostname, port) = if let Some((h, p)) = host_part.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(443))
        } else {
            (host_part.to_string(), 443)
        };
        let https_url = h3_url.replacen("h3://", "https://", 1);
        let pool_key = format!("{}:{}", hostname, port);
        Self {
            https_url,
            hostname,
            port,
            pool_key,
        }
    }

    async fn resolve_addr(&self, timeout: Duration) -> Result<std::net::SocketAddr, DomainError> {
        let target = format!("{}:{}", self.hostname, self.port);
        let mut addrs = tokio::time::timeout(timeout, tokio::net::lookup_host(target.clone()))
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: target.clone(),
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "DNS resolution failed for {}: {}",
                    target, e
                ))
            })?;
        addrs.next().ok_or_else(|| {
            DomainError::InvalidDomainName(format!("No address found for {}", target))
        })
    }

    async fn connect_new(&self, timeout: Duration) -> Result<H3SendRequest, DomainError> {
        let addr = self.resolve_addr(timeout).await?;

        let connecting = H3_QUIC_ENDPOINT
            .connect(addr, &self.hostname)
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Failed to initiate H3 connection to {}: {}",
                    addr, e
                ))
            })?;

        let quinn_conn = tokio::time::timeout(timeout, connecting)
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: addr.to_string(),
            })?
            .map_err(|e| DomainError::TransportConnectionRefused {
                server: format!("{}({}): {}", self.hostname, addr, e),
            })?;

        let h3_conn = h3_quinn::Connection::new(quinn_conn);
        let (mut driver, send_request) = h3::client::new(h3_conn).await.map_err(|e| {
            DomainError::InvalidDomainName(format!(
                "Failed to create H3 client for {}: {}",
                addr, e
            ))
        })?;

        tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        Ok(send_request)
    }

    async fn get_or_connect(&self, timeout: Duration) -> Result<H3SendRequest, DomainError> {
        if let Some(sr) = H3_POOL.get(&self.pool_key) {
            return Ok(sr.clone());
        }
        let send_request = self.connect_new(timeout).await?;
        H3_POOL.insert(self.pool_key.clone(), send_request.clone());
        Ok(send_request)
    }

    async fn execute_request(
        send_request: &mut H3SendRequest,
        https_url: &str,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Bytes, DomainError> {
        let request = http::Request::builder()
            .method("POST")
            .uri(https_url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(())
            .map_err(|e| {
                DomainError::InvalidDomainName(format!("Failed to build H3 request: {}", e))
            })?;

        let mut stream = tokio::time::timeout(timeout, send_request.send_request(request))
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: https_url.to_string(),
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Failed to send H3 request to {}: {}",
                    https_url, e
                ))
            })?;

        tokio::time::timeout(
            timeout,
            stream.send_data(Bytes::copy_from_slice(message_bytes)),
        )
        .await
        .map_err(|_| DomainError::TransportTimeout {
            server: https_url.to_string(),
        })?
        .map_err(|e| {
            DomainError::InvalidDomainName(format!(
                "Failed to send H3 data to {}: {}",
                https_url, e
            ))
        })?;

        tokio::time::timeout(timeout, stream.finish())
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: https_url.to_string(),
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Failed to finish H3 stream to {}: {}",
                    https_url, e
                ))
            })?;

        let response = tokio::time::timeout(timeout, stream.recv_response())
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: https_url.to_string(),
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Failed to receive H3 response from {}: {}",
                    https_url, e
                ))
            })?;

        if !response.status().is_success() {
            return Err(DomainError::InvalidDomainName(format!(
                "H3 server {} returned HTTP {}",
                https_url,
                response.status().as_u16()
            )));
        }

        let mut body = BytesMut::new();
        while let Some(mut chunk) = tokio::time::timeout(timeout, stream.recv_data())
            .await
            .map_err(|_| DomainError::TransportTimeout {
                server: https_url.to_string(),
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
                    "Failed to read H3 body from {}: {}",
                    https_url, e
                ))
            })?
        {
            body.extend_from_slice(chunk.chunk());
            chunk.advance(chunk.remaining());
        }

        Ok(body.freeze())
    }
}

#[async_trait]
impl DnsTransport for H3Transport {
    async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        let mut send_request = self.get_or_connect(timeout).await?;

        match Self::execute_request(&mut send_request, &self.https_url, message_bytes, timeout)
            .await
        {
            Ok(response_bytes) => {
                debug!(url = %self.https_url, "DoH3 query via pooled connection");
                return Ok(TransportResponse {
                    bytes: response_bytes,
                    protocol_used: "H3",
                });
            }
            Err(_) => {
                H3_POOL.remove(&self.pool_key);
                debug!(url = %self.https_url, "H3 connection stale, reconnecting");
            }
        }

        let mut fresh_request = self.connect_new(timeout).await?;
        H3_POOL.insert(self.pool_key.clone(), fresh_request.clone());

        let response_bytes =
            Self::execute_request(&mut fresh_request, &self.https_url, message_bytes, timeout)
                .await?;

        debug!(
            url = %self.https_url,
            response_len = response_bytes.len(),
            "DoH3 response received"
        );

        Ok(TransportResponse {
            bytes: response_bytes,
            protocol_used: "H3",
        })
    }

    fn protocol_name(&self) -> &'static str {
        "H3"
    }
}
