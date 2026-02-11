use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::sync::LazyLock;
use std::time::Duration;
use tracing::debug;

/// Shared HTTP/2 client with connection pooling.
static SHARED_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .use_rustls_tls()
        .timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(4)
        .http2_prior_knowledge()
        .build()
        .unwrap_or_else(|_| reqwest::Client::new())
});

/// Expected content type for DNS-over-HTTPS responses (RFC 8484 §4.2.1)
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// DNS-over-HTTPS transport (RFC 8484)
pub struct HttpsTransport {
    url: String,
}

impl HttpsTransport {
    pub fn new(url: String) -> Self {
        Self { url }
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

        // POST with application/dns-message (RFC 8484 §4.1)
        let response = tokio::time::timeout(
            timeout,
            SHARED_CLIENT
                .post(&self.url)
                .header("Content-Type", DNS_MESSAGE_CONTENT_TYPE)
                .header("Accept", DNS_MESSAGE_CONTENT_TYPE)
                .body(message_bytes.to_vec())
                .send(),
        )
        .await
        .map_err(|_| {
            DomainError::InvalidDomainName(format!("Timeout sending DoH query to {}", self.url))
        })?
        .map_err(|e| {
            DomainError::InvalidDomainName(format!("DoH request to {} failed: {}", self.url, e))
        })?;

        // Check HTTP status
        let status = response.status();
        if !status.is_success() {
            return Err(DomainError::InvalidDomainName(format!(
                "DoH server {} returned HTTP {}: {}",
                self.url,
                status.as_u16(),
                status.canonical_reason().unwrap_or("Unknown")
            )));
        }

        // Read response body (raw DNS message)
        let response_bytes = tokio::time::timeout(timeout, response.bytes())
            .await
            .map_err(|_| {
                DomainError::InvalidDomainName(format!(
                    "Timeout reading DoH response from {}",
                    self.url
                ))
            })?
            .map_err(|e| {
                DomainError::InvalidDomainName(format!(
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
            bytes: response_bytes.to_vec(),
            protocol_used: "HTTPS",
        })
    }

    fn protocol_name(&self) -> &'static str {
        "HTTPS"
    }
}
