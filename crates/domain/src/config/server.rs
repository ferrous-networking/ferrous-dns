use serde::{Deserialize, Serialize};

use super::encrypted_dns::EncryptedDnsConfig;
use super::web_tls::WebTlsConfig;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub dns_port: u16,

    pub web_port: u16,

    /// Default address every listener binds to. `"0.0.0.0"` covers all IPv4
    /// interfaces; `"[::]"` covers both families on one dual-stack socket.
    /// A bare `"::"` is accepted too — the brackets are added when the
    /// listen address is built.
    pub bind_address: String,

    #[serde(default = "default_cors_origins")]
    pub cors_allowed_origins: Vec<String>,

    #[serde(default)]
    pub encrypted_dns: EncryptedDnsConfig,

    #[serde(default)]
    pub proxy_protocol_enabled: bool,

    /// When `true`, mounts the Pi-hole v6 compatible API at `/api/*` and
    /// moves the Ferrous dashboard API to `/ferrous/api/*`.
    /// The frontend discovers the correct prefix via `/ferrous-config.js`.
    /// Defaults to `false` — no change in behaviour for existing deployments.
    #[serde(default)]
    pub pihole_compat: bool,

    #[serde(default)]
    pub web_tls: WebTlsConfig,

    /// When `true`, serves a Prometheus text-exposition endpoint at `/metrics`
    /// on the web port, unauthenticated. Opt-in; defaults to `false`.
    #[serde(default)]
    pub metrics_enabled: bool,
}

fn default_cors_origins() -> Vec<String> {
    vec!["*".to_string()]
}

impl ServerConfig {
    /// Listen address for plain DNS (Do53), shared by the UDP and TCP listeners.
    pub fn dns_listen_address(&self) -> String {
        join_host_port(&self.bind_address, self.dns_port)
    }

    /// Listen address for the web dashboard and REST API.
    pub fn web_listen_address(&self) -> String {
        join_host_port(&self.bind_address, self.web_port)
    }

    /// Listen address for the DoT listener, honouring
    /// `[server.encrypted_dns].dot_bind_address` when it is set.
    pub fn dot_listen_address(&self) -> String {
        join_host_port(
            self.encrypted_dns
                .dot_bind_address
                .as_deref()
                .unwrap_or(&self.bind_address),
            self.encrypted_dns.dot_port,
        )
    }

    /// Listen address for the DoQ listener, honouring
    /// `[server.encrypted_dns].doq_bind_address` when it is set.
    pub fn doq_listen_address(&self) -> String {
        join_host_port(
            self.encrypted_dns
                .doq_bind_address
                .as_deref()
                .unwrap_or(&self.bind_address),
            self.encrypted_dns.doq_port,
        )
    }

    /// Listen address for the dedicated DoH listener, or `None` when
    /// `doh_port` is absent and `/dns-query` is co-hosted on `web_port`.
    pub fn doh_listen_address(&self) -> Option<String> {
        let port = self.encrypted_dns.doh_port?;
        Some(join_host_port(
            self.encrypted_dns
                .doh_bind_address
                .as_deref()
                .unwrap_or(&self.bind_address),
            port,
        ))
    }
}

/// Joins a bind host with a port. A bare IPv6 literal is bracketed, so both
/// `"::"` and `"[::]"` yield an address that parses as a `SocketAddr`.
fn join_host_port(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        return format!("[{host}]:{port}");
    }
    format!("{host}:{port}")
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            dns_port: 53,
            web_port: 8080,
            bind_address: "0.0.0.0".to_string(),
            cors_allowed_origins: default_cors_origins(),
            encrypted_dns: EncryptedDnsConfig::default(),
            proxy_protocol_enabled: false,
            pihole_compat: false,
            web_tls: WebTlsConfig::default(),
            metrics_enabled: false,
        }
    }
}
