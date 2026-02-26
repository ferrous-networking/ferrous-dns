use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

/// Represents an upstream server address that may or may not be resolved to an IP.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UpstreamAddr {
    Resolved(SocketAddr),
    Unresolved { hostname: Arc<str>, port: u16 },
}

impl UpstreamAddr {
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            UpstreamAddr::Resolved(addr) => Some(*addr),
            UpstreamAddr::Unresolved { .. } => None,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            UpstreamAddr::Resolved(addr) => addr.port(),
            UpstreamAddr::Unresolved { port, .. } => *port,
        }
    }

    pub fn hostname_str(&self) -> Option<&str> {
        match self {
            UpstreamAddr::Resolved(_) => None,
            UpstreamAddr::Unresolved { hostname, .. } => Some(hostname),
        }
    }

    pub fn is_unresolved(&self) -> bool {
        matches!(self, UpstreamAddr::Unresolved { .. })
    }

    /// Returns (hostname, port) if this address is unresolved.
    pub fn unresolved_parts(&self) -> Option<(&str, u16)> {
        match self {
            UpstreamAddr::Unresolved { hostname, port } => Some((hostname, *port)),
            UpstreamAddr::Resolved(_) => None,
        }
    }
}

impl fmt::Display for UpstreamAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UpstreamAddr::Resolved(addr) => write!(f, "{}", addr),
            UpstreamAddr::Unresolved { hostname, port } => write!(f, "{}:{}", hostname, port),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsProtocol {
    Udp {
        addr: UpstreamAddr,
    },
    Tcp {
        addr: UpstreamAddr,
    },
    Tls {
        addr: UpstreamAddr,
        hostname: Arc<str>,
    },
    Https {
        url: Arc<str>,
        hostname: Arc<str>,
        resolved_addrs: Vec<SocketAddr>,
    },
    Quic {
        addr: UpstreamAddr,
        hostname: Arc<str>,
    },
    H3 {
        url: Arc<str>,
        hostname: Arc<str>,
        resolved_addrs: Vec<SocketAddr>,
    },
}

impl DnsProtocol {
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            DnsProtocol::Udp { addr }
            | DnsProtocol::Tcp { addr }
            | DnsProtocol::Tls { addr, .. }
            | DnsProtocol::Quic { addr, .. } => addr.socket_addr(),
            DnsProtocol::Https { .. } | DnsProtocol::H3 { .. } => None,
        }
    }

    pub fn hostname(&self) -> Option<&str> {
        match self {
            DnsProtocol::Tls { hostname, .. }
            | DnsProtocol::Https { hostname, .. }
            | DnsProtocol::Quic { hostname, .. }
            | DnsProtocol::H3 { hostname, .. } => Some(hostname),
            _ => None,
        }
    }

    pub fn url(&self) -> Option<&str> {
        match self {
            DnsProtocol::Https { url, .. } | DnsProtocol::H3 { url, .. } => Some(url),
            _ => None,
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        match self {
            DnsProtocol::Udp { .. } => "UDP",
            DnsProtocol::Tcp { .. } => "TCP",
            DnsProtocol::Tls { .. } => "TLS",
            DnsProtocol::Https { .. } => "HTTPS",
            DnsProtocol::Quic { .. } => "QUIC",
            DnsProtocol::H3 { .. } => "H3",
        }
    }

    /// Returns `true` if this protocol has an unresolved hostname that needs DNS resolution.
    pub fn needs_resolution(&self) -> bool {
        match self {
            DnsProtocol::Udp { addr }
            | DnsProtocol::Tcp { addr }
            | DnsProtocol::Tls { addr, .. }
            | DnsProtocol::Quic { addr, .. } => addr.is_unresolved(),
            DnsProtocol::Https {
                hostname,
                resolved_addrs,
                ..
            }
            | DnsProtocol::H3 {
                hostname,
                resolved_addrs,
                ..
            } => hostname.parse::<std::net::IpAddr>().is_err() && resolved_addrs.is_empty(),
        }
    }

    /// Creates a copy of this protocol with the given resolved `SocketAddr`.
    /// Used by PoolManager to expand hostnames into concrete IP addresses.
    pub fn with_resolved_addr(&self, resolved: SocketAddr) -> Self {
        match self {
            DnsProtocol::Udp { .. } => DnsProtocol::Udp {
                addr: UpstreamAddr::Resolved(resolved),
            },
            DnsProtocol::Tcp { .. } => DnsProtocol::Tcp {
                addr: UpstreamAddr::Resolved(resolved),
            },
            DnsProtocol::Tls { hostname, .. } => DnsProtocol::Tls {
                addr: UpstreamAddr::Resolved(resolved),
                hostname: hostname.clone(),
            },
            DnsProtocol::Quic { hostname, .. } => DnsProtocol::Quic {
                addr: UpstreamAddr::Resolved(resolved),
                hostname: hostname.clone(),
            },
            DnsProtocol::Https { .. } | DnsProtocol::H3 { .. } => self.clone(),
        }
    }

    pub fn with_resolved_addrs(&self, addrs: Vec<SocketAddr>) -> Self {
        match self {
            DnsProtocol::Https { url, hostname, .. } => DnsProtocol::Https {
                url: url.clone(),
                hostname: hostname.clone(),
                resolved_addrs: addrs,
            },
            DnsProtocol::H3 { url, hostname, .. } => DnsProtocol::H3 {
                url: url.clone(),
                hostname: hostname.clone(),
                resolved_addrs: addrs,
            },
            _ => self.clone(),
        }
    }
}

fn parse_host_port(s: &str) -> Option<(&str, u16)> {
    if s.starts_with('[') {
        let end = s.find(']')?;
        let host = &s[1..end];
        let rest = &s[end + 1..];
        let port_str = rest.strip_prefix(':')?;
        let port = port_str.parse::<u16>().ok()?;
        Some((host, port))
    } else {
        let (host, port_str) = s.rsplit_once(':')?;
        let port = port_str.parse::<u16>().ok()?;
        Some((host, port))
    }
}

fn parse_upstream_addr(addr_str: &str) -> Result<UpstreamAddr, String> {
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Ok(UpstreamAddr::Resolved(addr));
    }
    if let Some((host, port)) = parse_host_port(addr_str) {
        return Ok(UpstreamAddr::Unresolved {
            hostname: host.into(),
            port,
        });
    }
    Err(format!("Invalid address '{}'", addr_str))
}

impl FromStr for DnsProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(addr_str) = s.strip_prefix("udp://") {
            let addr = parse_upstream_addr(addr_str)
                .map_err(|_| format!("Invalid UDP address '{}'", addr_str))?;
            return Ok(DnsProtocol::Udp { addr });
        }
        if let Some(addr_str) = s.strip_prefix("tcp://") {
            let addr = parse_upstream_addr(addr_str)
                .map_err(|_| format!("Invalid TCP address '{}'", addr_str))?;
            return Ok(DnsProtocol::Tcp { addr });
        }
        if let Some(rest) = s.strip_prefix("tls://") {
            if let Ok(addr) = rest.parse::<SocketAddr>() {
                let hostname: Arc<str> = rest.split(':').next().unwrap_or(rest).into();
                return Ok(DnsProtocol::Tls {
                    addr: UpstreamAddr::Resolved(addr),
                    hostname,
                });
            }
            if let Some((host, port_str)) = rest.rsplit_once(':') {
                let port = port_str
                    .parse::<u16>()
                    .map_err(|e| format!("Invalid port in TLS address '{}': {}", rest, e))?;
                return Ok(DnsProtocol::Tls {
                    addr: UpstreamAddr::Unresolved {
                        hostname: host.into(),
                        port,
                    },
                    hostname: host.into(),
                });
            }
            return Err(format!(
                "Invalid TLS format '{}'. Expected 'tls://IP:PORT' or 'tls://HOSTNAME:PORT'",
                s
            ));
        }
        if let Some(rest) = s.strip_prefix("doq://") {
            if let Ok(addr) = rest.parse::<SocketAddr>() {
                let hostname: Arc<str> = rest.split(':').next().unwrap_or(rest).into();
                return Ok(DnsProtocol::Quic {
                    addr: UpstreamAddr::Resolved(addr),
                    hostname,
                });
            }
            if let Some((host, port_str)) = rest.rsplit_once(':') {
                let port = port_str
                    .parse::<u16>()
                    .map_err(|e| format!("Invalid port in QUIC address '{}': {}", rest, e))?;
                return Ok(DnsProtocol::Quic {
                    addr: UpstreamAddr::Unresolved {
                        hostname: host.into(),
                        port,
                    },
                    hostname: host.into(),
                });
            }
            return Err(format!(
                "Invalid QUIC format '{}'. Expected 'doq://IP:PORT' or 'doq://HOSTNAME:PORT'",
                s
            ));
        }
        if s.starts_with("h3://") {
            let url: Arc<str> = s.into();
            let hostname: Arc<str> = s
                .strip_prefix("h3://")
                .and_then(|rest| rest.split('/').next())
                .ok_or_else(|| format!("Invalid H3 URL: {}", s))?
                .into();
            return Ok(DnsProtocol::H3 {
                url,
                hostname,
                resolved_addrs: vec![],
            });
        }
        if s.starts_with("https://") {
            let url: Arc<str> = s.into();
            let hostname: Arc<str> = s
                .strip_prefix("https://")
                .and_then(|rest| rest.split('/').next())
                .ok_or_else(|| format!("Invalid HTTPS URL: {}", s))?
                .into();
            return Ok(DnsProtocol::Https {
                url,
                hostname,
                resolved_addrs: vec![],
            });
        }
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(DnsProtocol::Udp {
                addr: UpstreamAddr::Resolved(addr),
            });
        }
        Err(format!("Invalid DNS endpoint format: '{}'. Expected: udp://IP:PORT, tcp://IP:PORT, tls://HOST:PORT, https://URL, h3://URL, doq://HOST:PORT, or IP:PORT", s))
    }
}

impl fmt::Display for DnsProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsProtocol::Udp { addr } => write!(f, "udp://{}", addr),
            DnsProtocol::Tcp { addr } => write!(f, "tcp://{}", addr),
            DnsProtocol::Tls { addr, hostname } => {
                write!(f, "tls://{}:{}", hostname, addr.port())
            }
            DnsProtocol::Https { url, .. } => write!(f, "{}", url),
            DnsProtocol::H3 { url, .. } => write!(f, "{}", url),
            DnsProtocol::Quic { addr, hostname } => {
                write!(f, "doq://{}:{}", hostname, addr.port())
            }
        }
    }
}
