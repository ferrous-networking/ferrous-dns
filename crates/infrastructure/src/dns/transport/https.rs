use super::{doh_response_too_large, DnsTransport, TransportResponse, MAX_DOH_MESSAGE_SIZE};
use async_trait::async_trait;
use bytes::BytesMut;
use ferrous_dns_domain::DomainError;
use std::net::SocketAddr;
use std::sync::{LazyLock, OnceLock};
use std::time::{Duration, Instant};
use tracing::debug;

static SHARED_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .use_rustls_tls()
        .pool_max_idle_per_host(4)
        .http2_prior_knowledge()
        .tcp_keepalive(Duration::from_secs(15))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

pub struct HttpsTransport {
    url: String,
    hostname: String,
    resolved_addrs: Vec<SocketAddr>,
    client: OnceLock<reqwest::Client>,
}

impl HttpsTransport {
    pub fn new(url: String, hostname: String, resolved_addrs: Vec<SocketAddr>) -> Self {
        Self {
            url,
            hostname,
            resolved_addrs,
            client: OnceLock::new(),
        }
    }

    fn get_or_create_client(&self) -> &reqwest::Client {
        // The transport cache keys resolved addresses too; client lifetime follows that snapshot.
        self.client.get_or_init(|| {
            if self.resolved_addrs.is_empty() {
                return SHARED_CLIENT.clone();
            }

            reqwest::Client::builder()
                .use_rustls_tls()
                .pool_max_idle_per_host(4)
                .http2_prior_knowledge()
                .tcp_keepalive(Duration::from_secs(15))
                .resolve_to_addrs(&self.hostname, &self.resolved_addrs)
                .build()
                .unwrap_or_else(|_| SHARED_CLIENT.clone())
        })
    }
}

#[async_trait]
impl DnsTransport for HttpsTransport {
    async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        debug!(
            url = %self.url,
            message_len = message_bytes.len(),
            "Sending DoH query"
        );

        let start = Instant::now();

        let client = self.get_or_create_client();

        let mut response = tokio::time::timeout(
            timeout,
            client
                .post(&self.url)
                .header("Content-Type", DNS_MESSAGE_CONTENT_TYPE)
                .header("Accept", DNS_MESSAGE_CONTENT_TYPE)
                .body(bytes::Bytes::copy_from_slice(message_bytes))
                .send(),
        )
        .await
        .map_err(|_| DomainError::IoError(format!("Timeout sending DoH query to {}", self.url)))?
        .map_err(|e| DomainError::IoError(format!("DoH request to {} failed: {}", self.url, e)))?;

        let status = response.status();
        if !status.is_success() {
            return Err(DomainError::IoError(format!(
                "DoH server {} returned HTTP {}: {}",
                self.url,
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            )));
        }

        let content_length = response.content_length();
        if content_length.is_some_and(|length| length > MAX_DOH_MESSAGE_SIZE as u64) {
            return Err(doh_response_too_large(&self.url));
        }
        enum Body {
            Single(bytes::Bytes),
            Multiple(BytesMut),
        }
        let mut body = Body::Single(bytes::Bytes::new());
        while let Some(chunk) = {
            let remaining = timeout.saturating_sub(start.elapsed());
            tokio::time::timeout(remaining, response.chunk())
                .await
                .map_err(|_| {
                    DomainError::IoError(format!("Timeout reading DoH response from {}", self.url))
                })?
                .map_err(|e| {
                    DomainError::IoError(format!(
                        "Failed to read DoH response from {}: {}",
                        self.url, e
                    ))
                })?
        } {
            let body_len = match &body {
                Body::Single(bytes) => bytes.len(),
                Body::Multiple(bytes) => bytes.len(),
            };
            if chunk.len() > MAX_DOH_MESSAGE_SIZE - body_len {
                return Err(doh_response_too_large(&self.url));
            }
            match &mut body {
                Body::Single(first) if first.is_empty() => *first = chunk,
                Body::Single(first) => {
                    let capacity = content_length.unwrap_or((body_len + chunk.len()) as u64);
                    let mut combined = BytesMut::with_capacity(capacity as usize);
                    combined.extend_from_slice(first);
                    combined.extend_from_slice(&chunk);
                    body = Body::Multiple(combined);
                }
                Body::Multiple(bytes) => bytes.extend_from_slice(&chunk),
            }
        }
        let response_bytes = match body {
            Body::Single(bytes) => bytes,
            Body::Multiple(bytes) => bytes.freeze(),
        };

        debug!(
            url = %self.url,
            response_len = response_bytes.len(),
            "DoH response received"
        );

        Ok(TransportResponse {
            bytes: response_bytes,
            protocol_used: "HTTPS",
        })
    }

    fn protocol_name(&self) -> &'static str {
        "HTTPS"
    }
}

#[cfg(test)]
mod tests {
    use super::{DnsTransport, HttpsTransport};
    use bytes::Bytes;
    use ferrous_dns_domain::DomainError;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn loopback_response(response: Vec<u8>) -> Result<Bytes, DomainError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let hostname = format!("response-limit-{}", addr.port());
        let client = reqwest::Client::builder()
            .no_proxy()
            .http1_only()
            .build()
            .unwrap();
        let transport = HttpsTransport::new(
            format!("http://{addr}/dns-query"),
            hostname.clone(),
            vec![addr],
        );
        transport.client.set(client).unwrap();
        let (consumed_tx, consumed_rx) = tokio::sync::oneshot::channel();
        let server = async {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                request.push(socket.read_u8().await.unwrap());
            }
            let mut query = [0; 12];
            socket.read_exact(&mut query).await.unwrap();
            socket.write_all(&response).await.unwrap();
            // Keep EOF withheld so an oversized response must be rejected while streaming.
            let _ = consumed_rx.await;
        };
        let client = async {
            let result = transport.send(&[0; 12], Duration::from_secs(30)).await;
            let _ = consumed_tx.send(());
            result.map(|response| response.bytes)
        };
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(server, client).1
        })
        .await;
        result.expect(
            "DoH response handling must finish without waiting for EOF or the request timeout",
        )
    }

    #[tokio::test]
    async fn test_https_rejects_oversized_responses_before_eof() {
        let advertised = b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n".to_vec();
        let mut streamed =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8000\r\n".to_vec();
        streamed.extend_from_slice(&[0; 32_768]);
        streamed.extend_from_slice(b"\r\n8000\r\n");
        streamed.extend_from_slice(&[0; 32_768]);
        streamed.extend_from_slice(b"\r\n");
        for response in [advertised, streamed] {
            assert!(matches!(
                loopback_response(response).await,
                Err(DomainError::IoError(_))
            ));
        }
    }

    #[tokio::test]
    async fn test_https_accepts_maximum_sized_response() {
        let expected = vec![42; 65_535];
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 65535\r\n\r\n".to_vec();
        response.extend_from_slice(&expected);
        assert_eq!(loopback_response(response).await.unwrap(), expected);
    }
}
