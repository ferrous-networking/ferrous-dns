use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use dashmap::DashMap;
use ferrous_dns_domain::DomainError;
use std::net::SocketAddr;
use std::sync::LazyLock;
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

const CLIENT_TTL: Duration = Duration::from_secs(300);

static HTTPS_CLIENT_POOL: LazyLock<DashMap<String, (reqwest::Client, Instant)>> =
    LazyLock::new(DashMap::new);

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

pub struct HttpsTransport {
    url: String,
    hostname: String,
    resolved_addrs: Vec<SocketAddr>,
}

impl HttpsTransport {
    pub fn new(url: String, hostname: String, resolved_addrs: Vec<SocketAddr>) -> Self {
        Self {
            url,
            hostname,
            resolved_addrs,
        }
    }

    fn get_or_create_client(hostname: &str, addrs: &[SocketAddr]) -> reqwest::Client {
        if let Some(entry) = HTTPS_CLIENT_POOL.get(hostname) {
            let (client, created_at) = entry.value();
            if created_at.elapsed() < CLIENT_TTL {
                return client.clone();
            }
            drop(entry);
            HTTPS_CLIENT_POOL.remove(hostname);
        }

        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .pool_max_idle_per_host(4)
            .http2_prior_knowledge()
            .tcp_keepalive(Duration::from_secs(15))
            .resolve_to_addrs(hostname, addrs)
            .build()
            .unwrap_or_else(|_| SHARED_CLIENT.clone());

        HTTPS_CLIENT_POOL
            .entry(hostname.to_string())
            .or_insert((client, Instant::now()))
            .clone()
            .0
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

        let client = if self.resolved_addrs.is_empty() {
            SHARED_CLIENT.clone()
        } else {
            Self::get_or_create_client(&self.hostname, &self.resolved_addrs)
        };

        let response = tokio::time::timeout(
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

        let remaining = timeout
            .checked_sub(start.elapsed())
            .unwrap_or(Duration::ZERO);

        let response_bytes = tokio::time::timeout(remaining, response.bytes())
            .await
            .map_err(|_| {
                DomainError::IoError(format!("Timeout reading DoH response from {}", self.url))
            })?
            .map_err(|e| {
                DomainError::IoError(format!(
                    "Failed to read DoH response from {}: {}",
                    self.url, e
                ))
            })?;

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
