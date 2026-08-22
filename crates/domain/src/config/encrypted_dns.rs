use serde::{Deserialize, Serialize};

/// Configuration for DoT, DoH, and DoQ server-side listeners.
///
/// All three protocols are disabled by default. Enabling any requires a valid TLS
/// certificate and private key in PEM format. Default paths point to `/data/`,
/// the standard Docker volume mount for Ferrous DNS containers.
///
/// If the cert/key files are absent at startup, the affected listeners are skipped
/// with a warning — the server continues to serve plain DNS normally.
///
/// Each listener binds to `[server].bind_address` unless it carries its own
/// `*_bind_address`, which lets a single deployment expose, say, DoT on every
/// interface while keeping DoQ on one address.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncryptedDnsConfig {
    /// Enable the DNS-over-TLS listener (RFC 7858) on `dot_port`.
    #[serde(default)]
    pub dot_enabled: bool,

    /// TCP port for DNS-over-TLS. Standard port is 853.
    #[serde(default = "default_dot_port")]
    pub dot_port: u16,

    /// Address the DoT listener binds to; falls back to `[server].bind_address`.
    /// `"[::]"` serves IPv4 and IPv6 clients on one dual-stack socket.
    #[serde(default)]
    pub dot_bind_address: Option<String>,

    /// Enable the DNS-over-HTTPS endpoint `/dns-query` (RFC 8484).
    /// HTTPS termination is handled by a reverse proxy (nginx/Traefik/Caddy).
    #[serde(default)]
    pub doh_enabled: bool,

    /// Dedicated TCP port for the DoH `/dns-query` endpoint.
    ///
    /// When set, a separate listener is bound on this port serving only DNS-over-HTTPS,
    /// allowing standard port 443 to be used via a reverse proxy.
    /// When absent, `/dns-query` is co-hosted on `web_port` alongside the dashboard.
    #[serde(default)]
    pub doh_port: Option<u16>,

    /// Address the dedicated DoH listener binds to; falls back to
    /// `[server].bind_address`. Ignored when `doh_port` is absent, since
    /// `/dns-query` is then co-hosted on the web listener.
    #[serde(default)]
    pub doh_bind_address: Option<String>,

    /// Enable the DNS-over-QUIC listener (RFC 9250) on `doq_port`.
    #[serde(default)]
    pub doq_enabled: bool,

    /// UDP port for DNS-over-QUIC. Standard port is 853 (shared numeral with
    /// `dot_port`; no collision since DoQ is UDP-based and DoT is TCP-based).
    #[serde(default = "default_dot_port")]
    pub doq_port: u16,

    /// Address the DoQ listener binds to; falls back to `[server].bind_address`.
    /// `"[::]"` serves IPv4 and IPv6 clients on one dual-stack socket.
    #[serde(default)]
    pub doq_bind_address: Option<String>,

    /// Path to the PEM certificate file shared by DoT, DoH, and DoQ.
    #[serde(default = "default_cert_path")]
    pub tls_cert_path: String,

    /// Path to the PEM private key file shared by DoT, DoH, and DoQ.
    #[serde(default = "default_key_path")]
    pub tls_key_path: String,
}

fn default_dot_port() -> u16 {
    853
}

fn default_cert_path() -> String {
    "/data/cert.pem".to_string()
}

fn default_key_path() -> String {
    "/data/key.pem".to_string()
}

impl Default for EncryptedDnsConfig {
    fn default() -> Self {
        Self {
            dot_enabled: false,
            dot_port: default_dot_port(),
            dot_bind_address: None,
            doh_enabled: false,
            doh_port: None,
            doh_bind_address: None,
            doq_enabled: false,
            doq_port: default_dot_port(),
            doq_bind_address: None,
            tls_cert_path: default_cert_path(),
            tls_key_path: default_key_path(),
        }
    }
}
