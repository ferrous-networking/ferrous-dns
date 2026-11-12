use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use ipnetwork::{IpNetwork, Ipv4Network};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::encrypted_dns::EncryptedDnsConfig;
use super::web_tls::WebTlsConfig;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub dns_port: u16,

    pub web_port: u16,

    /// Default address every listener binds to. `"auto"`, the default, and
    /// `"[::]"` (or a bare `"::"`) cover both families on one dual-stack
    /// socket, `"auto"` only IPv4 on a kernel without IPv6; `"0.0.0.0"`
    /// covers all IPv4 interfaces only.
    #[serde(default)]
    pub bind_address: BindAddress,

    /// Address the web dashboard and REST API bind to; falls back to
    /// `bind_address`. Lets the dashboard stay on loopback behind a reverse
    /// proxy while DNS serves the network.
    #[serde(default, deserialize_with = "deserialize_optional_bind_host")]
    pub web_bind_address: Option<IpAddr>,

    #[serde(default = "default_cors_origins")]
    pub cors_allowed_origins: Vec<String>,

    #[serde(default)]
    pub encrypted_dns: EncryptedDnsConfig,

    #[serde(default)]
    pub proxy_protocol_enabled: bool,

    /// When `true`, mounts the Pi-hole v6 compatible API at `/api/*`. The
    /// Ferrous API stays at `/ferrous/api/v1/*` either way.
    /// Defaults to `false` — no change in behaviour for existing deployments.
    #[serde(default)]
    pub pihole_compat: bool,

    #[serde(default)]
    pub web_tls: WebTlsConfig,

    /// When `true`, serves a Prometheus text-exposition endpoint at `/metrics`
    /// on the web port, unauthenticated. Opt-in; defaults to `false`.
    #[serde(default)]
    pub metrics_enabled: bool,

    /// Peers whose `X-Forwarded-For` / `X-Real-IP` headers are believed on DoH
    /// requests; every other request is attributed to its socket peer, so a
    /// client cannot pick its own identity (and with it its group's policy).
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<IpNetwork>,
}

fn default_cors_origins() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_trusted_proxies() -> Vec<IpNetwork> {
    [
        Ipv4Network::new_checked(Ipv4Addr::new(127, 0, 0, 0), 8).map(IpNetwork::V4),
        Some(IpNetwork::from(IpAddr::V6(Ipv6Addr::LOCALHOST))),
    ]
    .into_iter()
    .flatten()
    .collect()
}

impl ServerConfig {
    /// Listen address for plain DNS (Do53), shared by the UDP and TCP listeners.
    pub fn dns_listen_address(&self) -> SocketAddr {
        SocketAddr::new(self.bind_address.ip(), self.dns_port)
    }

    /// Listen address for the web dashboard and REST API, honouring
    /// `web_bind_address` when it is set.
    pub fn web_listen_address(&self) -> SocketAddr {
        SocketAddr::new(
            self.web_bind_address.unwrap_or(self.bind_address.ip()),
            self.web_port,
        )
    }

    /// Listen address for the DoT listener, honouring
    /// `[server.encrypted_dns].dot_bind_address` when it is set.
    pub fn dot_listen_address(&self) -> SocketAddr {
        SocketAddr::new(
            self.encrypted_dns
                .dot_bind_address
                .unwrap_or(self.bind_address.ip()),
            self.encrypted_dns.dot_port,
        )
    }

    /// Listen address for the DoQ listener, honouring
    /// `[server.encrypted_dns].doq_bind_address` when it is set.
    pub fn doq_listen_address(&self) -> SocketAddr {
        SocketAddr::new(
            self.encrypted_dns
                .doq_bind_address
                .unwrap_or(self.bind_address.ip()),
            self.encrypted_dns.doq_port,
        )
    }

    /// Listen address for the dedicated DoH listener, or `None` when
    /// `doh_port` is absent and `/dns-query` is co-hosted on `web_port`.
    pub fn doh_listen_address(&self) -> Option<SocketAddr> {
        let port = self.encrypted_dns.doh_port?;
        Some(SocketAddr::new(
            self.encrypted_dns
                .doh_bind_address
                .unwrap_or(self.bind_address.ip()),
            port,
        ))
    }
}

/// `[server] bind_address`: `"auto"` or an IP literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BindAddress {
    #[default]
    Auto,
    Ip(IpAddr),
}

impl BindAddress {
    /// The address the listeners bind. `Auto` is `[::]`, which every listener
    /// opens with `IPV6_V6ONLY` off, so it serves IPv4 clients too.
    pub fn ip(self) -> IpAddr {
        match self {
            Self::Auto => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            Self::Ip(ip) => ip,
        }
    }

    /// What it stands for on a kernel without IPv6: `Auto` is `0.0.0.0`, and
    /// an explicit address stays as written, so an IPv6 one still fails to bind.
    pub fn without_ipv6(self) -> Self {
        match self {
            Self::Auto => Self::Ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            explicit @ Self::Ip(_) => explicit,
        }
    }
}

impl FromStr for BindAddress {
    type Err = String;

    fn from_str(host: &str) -> Result<Self, Self::Err> {
        if host == "auto" {
            return Ok(Self::Auto);
        }
        parse_bind_host(host).map(Self::Ip).map_err(|_| {
            format!(
                "invalid bind address '{host}': it must be \"auto\" or an IPv4 or IPv6 literal such as 0.0.0.0 or [::], not a hostname"
            )
        })
    }
}

impl fmt::Display for BindAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Auto => f.write_str("auto"),
            Self::Ip(ip) => ip.fmt(f),
        }
    }
}

impl Serialize for BindAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for BindAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Parses a listener host: an IPv4 literal, or an IPv6 literal with or
/// without brackets (`"::"` and `"[::]"` are the same address).
pub fn parse_bind_host(host: &str) -> Result<IpAddr, String> {
    let parsed = match host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        Some(v6) => v6.parse::<Ipv6Addr>().map(IpAddr::V6).ok(),
        None => host.parse::<IpAddr>().ok(),
    };
    parsed.ok_or_else(|| {
        format!(
            "invalid bind address '{host}': it must be an IPv4 or IPv6 literal such as 0.0.0.0 or [::], not a hostname"
        )
    })
}

pub(super) fn deserialize_optional_bind_host<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<IpAddr>, D::Error> {
    Option::<String>::deserialize(deserializer)?
        .map(|host| parse_bind_host(&host).map_err(serde::de::Error::custom))
        .transpose()
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            dns_port: 53,
            web_port: 8080,
            bind_address: BindAddress::Auto,
            web_bind_address: None,
            cors_allowed_origins: default_cors_origins(),
            encrypted_dns: EncryptedDnsConfig::default(),
            proxy_protocol_enabled: false,
            pihole_compat: false,
            web_tls: WebTlsConfig::default(),
            metrics_enabled: false,
            trusted_proxies: default_trusted_proxies(),
        }
    }
}
