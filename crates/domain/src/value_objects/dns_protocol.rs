use crate::DomainError;
use std::fmt;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
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
        /// URL host without brackets or port: the name the certificate is checked against.
        hostname: Arc<str>,
        port: u16,
        resolved_addrs: Vec<SocketAddr>,
    },
    Quic {
        addr: UpstreamAddr,
        hostname: Arc<str>,
    },
    H3 {
        url: Arc<str>,
        /// URL host without brackets or port: the name the certificate is checked against.
        hostname: Arc<str>,
        port: u16,
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
            DnsProtocol::Udp { .. } | DnsProtocol::Tcp { .. } => None,
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
            } => hostname.parse::<IpAddr>().is_err() && resolved_addrs.is_empty(),
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
            DnsProtocol::Https {
                url,
                hostname,
                port,
                ..
            } => DnsProtocol::Https {
                url: url.clone(),
                hostname: hostname.clone(),
                port: *port,
                resolved_addrs: addrs,
            },
            DnsProtocol::H3 {
                url,
                hostname,
                port,
                ..
            } => DnsProtocol::H3 {
                url: url.clone(),
                hostname: hostname.clone(),
                port: *port,
                resolved_addrs: addrs,
            },
            DnsProtocol::Udp { .. }
            | DnsProtocol::Tcp { .. }
            | DnsProtocol::Tls { .. }
            | DnsProtocol::Quic { .. } => self.clone(),
        }
    }
}

const SUPPORTED_SCHEMES: &str = "use udp://, tcp://, tls://, doq://, https:// or h3://";

enum HostPortError {
    MissingPort,
    Invalid(String),
}

impl HostPortError {
    fn into_hint(self, scheme: &str, rest: &str) -> String {
        match self {
            HostPortError::MissingPort => missing_port_hint(scheme, rest.trim_end_matches('/')),
            HostPortError::Invalid(hint) => hint,
        }
    }
}

/// Splits `HOST:PORT` or `[IPv6]:PORT`; the host comes back without brackets.
fn split_host_port(s: &str) -> Result<(&str, u16), HostPortError> {
    let (host, port) = match s.strip_prefix('[') {
        Some(bracketed) => {
            let (host, after) = bracketed
                .split_once(']')
                .ok_or_else(|| HostPortError::Invalid("unterminated IPv6 literal".into()))?;
            if after.is_empty() {
                return Err(HostPortError::MissingPort);
            }
            let port = after.strip_prefix(':').ok_or_else(|| {
                HostPortError::Invalid("unexpected characters after IPv6 literal".into())
            })?;
            (host, port)
        }
        None => s.rsplit_once(':').ok_or(HostPortError::MissingPort)?,
    };
    if host.is_empty() {
        return Err(HostPortError::Invalid("missing host".into()));
    }
    Ok((host, parse_port(port).map_err(HostPortError::Invalid)?))
}

fn parse_port(port: &str) -> Result<u16, String> {
    port.parse::<u16>()
        .map_err(|_| format!("invalid port '{port}' — use a number from 0 to 65535"))
}

/// `written` is the address as the user should write it, before the port.
fn missing_port_hint(scheme: &str, written: &str) -> String {
    let (protocol, port) = match scheme {
        "tls" => ("DNS-over-TLS", 853),
        "doq" => ("DNS-over-QUIC", 853),
        _ => ("plain DNS", 53),
    };
    let prefix = if scheme.is_empty() {
        String::new()
    } else {
        format!("{scheme}://")
    };
    format!("missing port — {protocol} usually uses {port}, e.g. {prefix}{written}:{port}")
}

/// AdGuard's dashboard and AdGuard Home write DoQ as `quic://HOST`, often without a port.
fn quic_scheme_hint(rest: &str) -> String {
    let rest = rest.trim_end_matches('/');
    let port = match split_host_port(rest) {
        Err(HostPortError::MissingPort) => ":853",
        _ => "",
    };
    format!("'quic://' is not a supported scheme — write DNS-over-QUIC as doq://{rest}{port}")
}

/// The returned name is what the peer certificate is checked against; IPs stay unbracketed.
fn parse_named_addr(scheme: &str, rest: &str) -> Result<(UpstreamAddr, Arc<str>), String> {
    if let Ok(addr) = rest.parse::<SocketAddr>() {
        return Ok((UpstreamAddr::Resolved(addr), addr.ip().to_string().into()));
    }
    let (host, port) = split_host_port(rest).map_err(|e| e.into_hint(scheme, rest))?;
    let hostname: Arc<str> = host.into();
    Ok((
        UpstreamAddr::Unresolved {
            hostname: hostname.clone(),
            port,
        },
        hostname,
    ))
}

/// Splits the authority of `rest` (a URL after its scheme) into the bare host,
/// IPv6 unbracketed, and the port, 443 when absent.
fn parse_url_authority(rest: &str) -> Result<(Arc<str>, u16), String> {
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (host, after) = bracketed
                .split_once(']')
                .ok_or("unterminated IPv6 literal")?;
            host.parse::<Ipv6Addr>()
                .map_err(|e| format!("invalid IPv6 literal '{host}': {e}"))?;
            let port = match after {
                "" => None,
                _ => Some(
                    after
                        .strip_prefix(':')
                        .ok_or("unexpected characters after IPv6 literal")?,
                ),
            };
            (host, port)
        }
        // A second colon can only come from an unbracketed IPv6 address.
        None if authority.matches(':').count() > 1 => {
            return Err(format!(
                "IPv6 addresses must be in brackets, e.g. [{authority}]"
            ));
        }
        None => match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() {
        return Err("missing host".into());
    }
    let port = match port {
        Some(port) => parse_port(port)?,
        None => 443,
    };
    Ok((host.into(), port))
}

fn parse_upstream_addr(scheme: &str, rest: &str) -> Result<UpstreamAddr, String> {
    if let Ok(addr) = rest.parse::<SocketAddr>() {
        return Ok(UpstreamAddr::Resolved(addr));
    }
    let (host, port) = split_host_port(rest).map_err(|e| e.into_hint(scheme, rest))?;
    Ok(UpstreamAddr::Unresolved {
        hostname: host.into(),
        port,
    })
}

/// Only `IP:PORT` may omit the scheme; it means plain UDP.
fn parse_bare(s: &str) -> Result<DnsProtocol, String> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(DnsProtocol::Udp {
            addr: UpstreamAddr::Resolved(addr),
        });
    }
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => return Err(missing_port_hint("", s)),
        Ok(IpAddr::V6(_)) => return Err(missing_port_hint("", &format!("[{s}]"))),
        Err(_) => {}
    }
    if is_host_like(s) {
        let port = if s.contains(':') { "" } else { ":53" };
        return Err(format!(
            "add a scheme, e.g. udp://{s}{port} — only IP:PORT may omit it"
        ));
    }
    Err("unrecognized server address — use a URL such as doq://dns.adguard-dns.com:853 or IP:PORT such as 8.8.8.8:53".into())
}

/// A DNS name or IPv4-looking token, optionally followed by `:DIGITS`.
fn is_host_like(s: &str) -> bool {
    let host = match s.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        Some(_) => return false,
        None => s,
    };
    !host.is_empty()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

fn parse_protocol(s: &str) -> Result<DnsProtocol, String> {
    let Some((scheme, rest)) = s.split_once("://") else {
        return parse_bare(s);
    };
    match scheme {
        "udp" => Ok(DnsProtocol::Udp {
            addr: parse_upstream_addr(scheme, rest)?,
        }),
        "tcp" => Ok(DnsProtocol::Tcp {
            addr: parse_upstream_addr(scheme, rest)?,
        }),
        "tls" => {
            let (addr, hostname) = parse_named_addr(scheme, rest)?;
            Ok(DnsProtocol::Tls { addr, hostname })
        }
        "doq" => {
            let (addr, hostname) = parse_named_addr(scheme, rest)?;
            Ok(DnsProtocol::Quic { addr, hostname })
        }
        "h3" => {
            let (hostname, port) = parse_url_authority(rest)?;
            Ok(DnsProtocol::H3 {
                url: s.into(),
                hostname,
                port,
                resolved_addrs: vec![],
            })
        }
        "https" => {
            let (hostname, port) = parse_url_authority(rest)?;
            Ok(DnsProtocol::Https {
                url: s.into(),
                hostname,
                port,
                resolved_addrs: vec![],
            })
        }
        "quic" => Err(quic_scheme_hint(rest)),
        _ => Err(format!(
            "unknown scheme '{scheme}://' — {SUPPORTED_SCHEMES}"
        )),
    }
}

impl FromStr for DnsProtocol {
    type Err = DomainError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        parse_protocol(s)
            .map_err(|hint| DomainError::ConfigError(format!("Invalid server '{s}': {hint}")))
    }
}

impl fmt::Display for DnsProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsProtocol::Udp { addr } => write!(f, "udp://{}", addr),
            DnsProtocol::Tcp { addr } => write!(f, "tcp://{}", addr),
            DnsProtocol::Tls { addr, hostname } => {
                write!(f, "tls://")?;
                write_host_port(f, hostname, addr.port())
            }
            DnsProtocol::Https { url, .. } => write!(f, "{}", url),
            DnsProtocol::H3 { url, .. } => write!(f, "{}", url),
            DnsProtocol::Quic { addr, hostname } => {
                write!(f, "doq://")?;
                write_host_port(f, hostname, addr.port())
            }
        }
    }
}

fn write_host_port(f: &mut fmt::Formatter<'_>, host: &str, port: u16) -> fmt::Result {
    if host.contains(':') {
        write!(f, "[{host}]:{port}")
    } else {
        write!(f, "{host}:{port}")
    }
}
