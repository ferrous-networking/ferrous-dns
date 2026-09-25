#[cfg(feature = "dns-over-h3")]
pub mod h3;
pub mod https;
#[cfg(feature = "dns-over-quic")]
pub mod quic;
pub mod resolver;
pub mod tcp;
pub mod tls;
pub mod udp;
pub mod udp_pool;

use bytes::Bytes;
use dashmap::DashMap;
use ferrous_dns_domain::{DnsProtocol, DomainError, UpstreamAddr};
use rustc_hash::FxBuildHasher;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

// RFC 8484 §6 bounds application/dns-message independently of HTTP framing.
const MAX_DOH_MESSAGE_SIZE: usize = u16::MAX as usize;

fn doh_response_too_large(url: &str) -> DomainError {
    DomainError::IoError(format!(
        "DoH response from {url} exceeds {MAX_DOH_MESSAGE_SIZE} bytes"
    ))
}

pub enum Transport {
    Udp(udp::UdpTransport),
    Tcp(tcp::TcpTransport),
    #[cfg(feature = "dns-over-rustls")]
    Tls(tls::TlsTransport),
    #[cfg(feature = "dns-over-https")]
    Https(https::HttpsTransport),
    #[cfg(feature = "dns-over-h3")]
    H3(h3::H3Transport),
    #[cfg(feature = "dns-over-quic")]
    Quic(quic::QuicTransport),
}

impl Transport {
    pub async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<Bytes, DomainError> {
        match self {
            Self::Udp(t) => t.send(message_bytes, timeout).await,
            Self::Tcp(t) => t.send(message_bytes, timeout).await,
            #[cfg(feature = "dns-over-rustls")]
            Self::Tls(t) => t.send(message_bytes, timeout).await,
            #[cfg(feature = "dns-over-https")]
            Self::Https(t) => t.send(message_bytes, timeout).await,
            #[cfg(feature = "dns-over-h3")]
            Self::H3(t) => t.send(message_bytes, timeout).await,
            #[cfg(feature = "dns-over-quic")]
            Self::Quic(t) => t.send(message_bytes, timeout).await,
        }
    }
}

static TRANSPORT_CACHE: LazyLock<DashMap<DnsProtocol, Arc<Transport>, FxBuildHasher>> =
    LazyLock::new(|| DashMap::with_hasher(FxBuildHasher));

pub fn get_or_create_transport(protocol: &DnsProtocol) -> Result<Arc<Transport>, DomainError> {
    if let Some(t) = TRANSPORT_CACHE.get(protocol) {
        return Ok(Arc::clone(t.value()));
    }
    let t = Arc::new(create_transport(protocol)?);
    // Concurrent creators must share the cached winner's connection pools.
    let entry = TRANSPORT_CACHE.entry(protocol.clone()).or_insert(t);
    Ok(Arc::clone(entry.value()))
}

fn create_transport(protocol: &DnsProtocol) -> Result<Transport, DomainError> {
    match protocol {
        DnsProtocol::Udp { addr } => Ok(Transport::Udp(udp::UdpTransport::new(addr.clone()))),
        DnsProtocol::Tcp { addr } => Ok(Transport::Tcp(tcp::TcpTransport::new(addr.clone()))),

        #[cfg(feature = "dns-over-rustls")]
        DnsProtocol::Tls { addr, hostname } => Ok(Transport::Tls(tls::TlsTransport::new(
            addr.clone(),
            hostname,
        )?)),

        #[cfg(not(feature = "dns-over-rustls"))]
        DnsProtocol::Tls { addr, .. } => Err(feature_disabled("TLS", "dns-over-rustls", addr)),

        #[cfg(feature = "dns-over-https")]
        DnsProtocol::Https {
            url,
            hostname,
            resolved_addrs,
            ..
        } => Ok(Transport::Https(https::HttpsTransport::new(
            url.to_string(),
            hostname,
            resolved_addrs.clone(),
        ))),

        #[cfg(not(feature = "dns-over-https"))]
        DnsProtocol::Https { url, .. } => Err(feature_disabled("HTTPS", "dns-over-https", url)),

        #[cfg(feature = "dns-over-quic")]
        DnsProtocol::Quic { addr, hostname } => Ok(Transport::Quic(quic::QuicTransport::new(
            addr.clone(),
            hostname.clone(),
        ))),

        #[cfg(not(feature = "dns-over-quic"))]
        DnsProtocol::Quic { addr, .. } => Err(feature_disabled("QUIC", "dns-over-quic", addr)),

        #[cfg(feature = "dns-over-h3")]
        DnsProtocol::H3 {
            url,
            hostname,
            port,
            resolved_addrs,
        } => Ok(Transport::H3(h3::H3Transport::new(
            url,
            hostname,
            *port,
            resolved_addrs.clone(),
        ))),

        #[cfg(not(feature = "dns-over-h3"))]
        DnsProtocol::H3 { url, .. } => Err(feature_disabled("H3", "dns-over-h3", url)),
    }
}

#[cfg(not(all(
    feature = "dns-over-rustls",
    feature = "dns-over-https",
    feature = "dns-over-quic",
    feature = "dns-over-h3"
)))]
fn feature_disabled(
    protocol: &str,
    feature: &str,
    endpoint: &impl std::fmt::Display,
) -> DomainError {
    DomainError::ConfigError(format!(
        "{protocol} feature not enabled. Enable '{feature}' feature to use: {endpoint}"
    ))
}

fn require_resolved(addr: &UpstreamAddr, label: &str) -> Result<SocketAddr, DomainError> {
    addr.socket_addr().ok_or_else(|| {
        DomainError::IoError(format!(
            "{label} upstream {addr} has no IP address yet: looking up its hostname failed. \
             It is retried automatically; if this machine uses Ferrous DNS as its own \
             resolver, set Local DNS server (Settings > DNS Settings) to your router"
        ))
    })
}

/// Client TLS for encrypted upstreams: webpki roots and session resumption.
fn tls_client_config() -> rustls::ClientConfig {
    // `builder()` needs a process-wide provider; a second install is a harmless error.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::in_memory_sessions(64);
    config
}

/// A QUIC client endpoint bound to `bind` that negotiates `alpn`.
#[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
fn quic_client_endpoint(bind: SocketAddr, alpn: &[u8]) -> Result<quinn::Endpoint, String> {
    let mut tls = tls_client_config();
    tls.alpn_protocols = vec![alpn.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|e| format!("QUIC TLS config: {e}"))?;
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(Duration::from_secs(15)));
    let mut config = quinn::ClientConfig::new(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    let mut endpoint = quinn::Endpoint::client(bind)
        .map_err(|e| format!("QUIC client endpoint on {bind}: {e}"))?;
    endpoint.set_default_client_config(config);
    Ok(endpoint)
}

/// The endpoint of the address family of `addr`, or the error that kept it from binding.
#[cfg(any(feature = "dns-over-quic", feature = "dns-over-h3"))]
fn endpoint_for<'a>(
    addr: &SocketAddr,
    v4: &'a Result<quinn::Endpoint, String>,
    v6: &'a Result<quinn::Endpoint, String>,
) -> Result<&'a quinn::Endpoint, DomainError> {
    let endpoint = if addr.is_ipv4() { v4 } else { v6 };
    endpoint
        .as_ref()
        .map_err(|e| DomainError::IoError(e.clone()))
}
