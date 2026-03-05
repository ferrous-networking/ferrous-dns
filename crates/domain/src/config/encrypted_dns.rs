use serde::{Deserialize, Serialize};

/// Configuration for DoT and DoH server-side listeners.
///
/// Both protocols are disabled by default. Enabling either requires a valid TLS
/// certificate and private key in PEM format. Default paths point to `/data/`,
/// the standard Docker volume mount for Ferrous DNS containers.
///
/// If the cert/key files are absent at startup, the affected listeners are skipped
/// with a warning — the server continues to serve plain DNS normally.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EncryptedDnsConfig {
    /// Enable the DNS-over-TLS listener (RFC 7858) on `dot_port`.
    #[serde(default)]
    pub dot_enabled: bool,

    /// TCP port for DNS-over-TLS. Standard port is 853.
    #[serde(default = "default_dot_port")]
    pub dot_port: u16,

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

    /// Path to the PEM certificate file shared by DoT and DoH.
    #[serde(default = "default_cert_path")]
    pub tls_cert_path: String,

    /// Path to the PEM private key file shared by DoT and DoH.
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
            doh_enabled: false,
            doh_port: None,
            tls_cert_path: default_cert_path(),
            tls_key_path: default_key_path(),
        }
    }
}
