use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsProtocol {
    Udp {
        addr: SocketAddr,
    },
    Tcp {
        addr: SocketAddr,
    },
    Tls {
        addr: SocketAddr,
        hostname: Arc<str>,
    },
    Https {
        url: Arc<str>,
        hostname: Arc<str>,
    },
    Quic {
        addr: SocketAddr,
        hostname: Arc<str>,
    },
    H3 {
        url: Arc<str>,
        hostname: Arc<str>,
    },
}

impl DnsProtocol {
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            DnsProtocol::Udp { addr }
            | DnsProtocol::Tcp { addr }
            | DnsProtocol::Tls { addr, .. }
            | DnsProtocol::Quic { addr, .. } => Some(*addr),
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
}

impl FromStr for DnsProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(addr_str) = s.strip_prefix("udp://") {
            let addr = addr_str
                .parse::<SocketAddr>()
                .map_err(|e| format!("Invalid UDP address '{}': {}", addr_str, e))?;
            return Ok(DnsProtocol::Udp { addr });
        }
        if let Some(addr_str) = s.strip_prefix("tcp://") {
            let addr = addr_str
                .parse::<SocketAddr>()
                .map_err(|e| format!("Invalid TCP address '{}': {}", addr_str, e))?;
            return Ok(DnsProtocol::Tcp { addr });
        }
        if let Some(rest) = s.strip_prefix("tls://") {
            if let Ok(addr) = rest.parse::<SocketAddr>() {
                let hostname: Arc<str> = rest.split(':').next().unwrap_or(rest).into();
                return Ok(DnsProtocol::Tls { addr, hostname });
            }
            if let Some((host, port_str)) = rest.rsplit_once(':') {
                let port = port_str
                    .parse::<u16>()
                    .map_err(|e| format!("Invalid port in TLS address '{}': {}", rest, e))?;
                let placeholder_addr = SocketAddr::from(([1, 1, 1, 1], port));
                return Ok(DnsProtocol::Tls {
                    addr: placeholder_addr,
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
                return Ok(DnsProtocol::Quic { addr, hostname });
            }
            if let Some((host, port_str)) = rest.rsplit_once(':') {
                let port = port_str
                    .parse::<u16>()
                    .map_err(|e| format!("Invalid port in QUIC address '{}': {}", rest, e))?;
                let addr = SocketAddr::from(([1, 1, 1, 1], port));
                return Ok(DnsProtocol::Quic {
                    addr,
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
            return Ok(DnsProtocol::H3 { url, hostname });
        }
        if s.starts_with("https://") {
            let url: Arc<str> = s.into();
            let hostname: Arc<str> = s
                .strip_prefix("https://")
                .and_then(|rest| rest.split('/').next())
                .ok_or_else(|| format!("Invalid HTTPS URL: {}", s))?
                .into();
            return Ok(DnsProtocol::Https { url, hostname });
        }
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(DnsProtocol::Udp { addr });
        }
        Err(format!("Invalid DNS endpoint format: '{}'. Expected: udp://IP:PORT, tcp://IP:PORT, tls://HOST:PORT, https://URL, h3://URL, doq://HOST:PORT, or IP:PORT", s))
    }
}

impl fmt::Display for DnsProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsProtocol::Udp { addr } => write!(f, "udp://{}", addr),
            DnsProtocol::Tcp { addr } => write!(f, "tcp://{}", addr),
            DnsProtocol::Tls { addr, hostname } => write!(f, "tls://{}:{}", hostname, addr.port()),
            DnsProtocol::Https { url, .. } => write!(f, "{}", url),
            DnsProtocol::H3 { url, .. } => write!(f, "{}", url),
            DnsProtocol::Quic { addr, hostname } => write!(f, "doq://{}:{}", hostname, addr.port()),
        }
    }
}
