pub mod https;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod udp_pool;

use async_trait::async_trait;
use ferrous_dns_domain::{DnsProtocol, DomainError};
use std::time::Duration;

// Re-export UDP pool for convenience
pub use udp_pool::{PoolStats, UdpSocketPool};

/// Result of a raw DNS transport operation
#[derive(Debug)]
pub struct TransportResponse {
    /// Raw DNS response bytes (wire format)
    pub bytes: Vec<u8>,
    /// Which protocol was used
    pub protocol_used: &'static str,
}

/// Trait for sending raw DNS messages over the wire
#[async_trait]
pub trait DnsTransport: Send + Sync {
    async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError>;

    fn protocol_name(&self) -> &'static str;
}

/// Enum-dispatched transport — stack-allocated, no Box/vtable overhead.
///
/// This replaces `Box<dyn DnsTransport>` with static dispatch via match.
/// For the hot path (UDP queries), this eliminates ~20ns of heap allocation
/// and virtual dispatch per query.
pub enum Transport {
    Udp(udp::UdpTransport),
    Tcp(tcp::TcpTransport),
    #[cfg(feature = "dns-over-rustls")]
    Tls(tls::TlsTransport),
    #[cfg(feature = "dns-over-https")]
    Https(https::HttpsTransport),
}

impl Transport {
    /// Send a DNS query via the appropriate protocol (static dispatch).
    pub async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        match self {
            Self::Udp(t) => DnsTransport::send(t, message_bytes, timeout).await,
            Self::Tcp(t) => DnsTransport::send(t, message_bytes, timeout).await,
            #[cfg(feature = "dns-over-rustls")]
            Self::Tls(t) => DnsTransport::send(t, message_bytes, timeout).await,
            #[cfg(feature = "dns-over-https")]
            Self::Https(t) => DnsTransport::send(t, message_bytes, timeout).await,
        }
    }

    /// Protocol name for logging and metrics.
    pub fn protocol_name(&self) -> &'static str {
        match self {
            Self::Udp(_) => "UDP",
            Self::Tcp(_) => "TCP",
            #[cfg(feature = "dns-over-rustls")]
            Self::Tls(_) => "TLS",
            #[cfg(feature = "dns-over-https")]
            Self::Https(_) => "HTTPS",
        }
    }
}

/// Create the appropriate transport for a given DnsProtocol (enum dispatch).
pub fn create_transport(protocol: &DnsProtocol) -> Result<Transport, DomainError> {
    match protocol {
        DnsProtocol::Udp { addr } => Ok(Transport::Udp(udp::UdpTransport::new(*addr))),
        DnsProtocol::Tcp { addr } => Ok(Transport::Tcp(tcp::TcpTransport::new(*addr))),

        #[cfg(feature = "dns-over-rustls")]
        DnsProtocol::Tls { addr, hostname } => Ok(Transport::Tls(tls::TlsTransport::new(
            *addr,
            hostname.to_string(),
        ))),

        #[cfg(not(feature = "dns-over-rustls"))]
        DnsProtocol::Tls { addr, .. } => {
            tracing::warn!("TLS feature not enabled, falling back to TCP for {}", addr);
            Ok(Transport::Tcp(tcp::TcpTransport::new(*addr)))
        }

        #[cfg(feature = "dns-over-https")]
        DnsProtocol::Https { url, .. } => Ok(Transport::Https(https::HttpsTransport::new(
            url.to_string(),
        ))),

        #[cfg(not(feature = "dns-over-https"))]
        DnsProtocol::Https { url, .. } => Err(DomainError::InvalidDomainName(format!(
            "HTTPS feature not enabled. Enable 'dns-over-https' feature to use: {}",
            url
        ))),
    }
}
