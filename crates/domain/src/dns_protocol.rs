use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

/// DNS Protocol types supported by Ferrous DNS
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DnsProtocol {
    /// UDP - Traditional DNS (port 53)
    /// Format: udp://1.1.1.1:53 or 1.1.1.1:53
    Udp { addr: SocketAddr },

    /// TCP - DNS over TCP (port 53)
    /// Format: tcp://1.1.1.1:53
    Tcp { addr: SocketAddr },

    /// TLS - DNS over TLS (port 853)
    /// Format: tls://1.1.1.1:853 or tls://cloudflare-dns.com:853
    ///
    /// **Note:** When using hostname format (e.g., tls://dns.google:853),
    /// the `addr` field will contain a placeholder IP (1.1.1.1) since
    /// DNS resolution cannot be done synchronously during parsing.
    /// The actual DNS resolution happens when Hickory DNS connects.
    /// The `hostname` field is used for TLS SNI (Server Name Indication).
    Tls { addr: SocketAddr, hostname: String },

    /// HTTPS - DNS over HTTPS (port 443)
    /// Format: https://1.1.1.1/dns-query or https://dns.google/dns-query
    Https { url: String, hostname: String },
}

impl DnsProtocol {
    /// Get socket address (if applicable)
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            DnsProtocol::Udp { addr } => Some(*addr),
            DnsProtocol::Tcp { addr } => Some(*addr),
            DnsProtocol::Tls { addr, .. } => Some(*addr),
            DnsProtocol::Https { .. } => None,
        }
    }

    /// Get hostname (for TLS/HTTPS)
    pub fn hostname(&self) -> Option<&str> {
        match self {
            DnsProtocol::Tls { hostname, .. } => Some(hostname),
            DnsProtocol::Https { hostname, .. } => Some(hostname),
            _ => None,
        }
    }

    /// Get URL (for HTTPS)
    pub fn url(&self) -> Option<&str> {
        match self {
            DnsProtocol::Https { url, .. } => Some(url),
            _ => None,
        }
    }

    /// Protocol name for display
    pub fn protocol_name(&self) -> &'static str {
        match self {
            DnsProtocol::Udp { .. } => "UDP",
            DnsProtocol::Tcp { .. } => "TCP",
            DnsProtocol::Tls { .. } => "TLS",
            DnsProtocol::Https { .. } => "HTTPS",
        }
    }
}

impl FromStr for DnsProtocol {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // UDP with protocol prefix
        if let Some(addr_str) = s.strip_prefix("udp://") {
            let addr = addr_str
                .parse::<SocketAddr>()
                .map_err(|e| format!("Invalid UDP address '{}': {}", addr_str, e))?;
            return Ok(DnsProtocol::Udp { addr });
        }

        // TCP with protocol prefix
        if let Some(addr_str) = s.strip_prefix("tcp://") {
            let addr = addr_str
                .parse::<SocketAddr>()
                .map_err(|e| format!("Invalid TCP address '{}': {}", addr_str, e))?;
            return Ok(DnsProtocol::Tcp { addr });
        }

        // TLS with protocol prefix
        if let Some(rest) = s.strip_prefix("tls://") {
            // Parse tls://IP:PORT or tls://HOSTNAME:PORT

            // Try to parse as IP:PORT first
            if let Ok(addr) = rest.parse::<SocketAddr>() {
                // IP address - use it directly
                let hostname = rest.split(':').next().unwrap_or(rest).to_string();
                return Ok(DnsProtocol::Tls { addr, hostname });
            }

            // Not a valid IP:PORT, try HOSTNAME:PORT
            if let Some((host, port_str)) = rest.rsplit_once(':') {
                let port = port_str
                    .parse::<u16>()
                    .map_err(|e| format!("Invalid port in TLS address '{}': {}", rest, e))?;

                // For hostname, we'll use a placeholder IP (1.1.1.1)
                // The actual DNS resolution will happen when connecting
                // This is a limitation of synchronous parsing
                let placeholder_addr = SocketAddr::from(([1, 1, 1, 1], port));

                return Ok(DnsProtocol::Tls {
                    addr: placeholder_addr,
                    hostname: host.to_string(),
                });
            }

            return Err(format!(
                "Invalid TLS format '{}'. Expected 'tls://IP:PORT' or 'tls://HOSTNAME:PORT'",
                s
            ));
        }

        // HTTPS with protocol prefix
        if s.starts_with("https://") {
            // Extract hostname from URL
            let url = s.to_string();
            let hostname = url
                .strip_prefix("https://")
                .and_then(|rest| rest.split('/').next())
                .ok_or_else(|| format!("Invalid HTTPS URL: {}", s))?
                .to_string();

            return Ok(DnsProtocol::Https { url, hostname });
        }

        // Default: Assume UDP if no protocol specified
        // Format: 1.1.1.1:53 or just IP:port
        if let Ok(addr) = s.parse::<SocketAddr>() {
            return Ok(DnsProtocol::Udp { addr });
        }

        Err(format!(
            "Invalid DNS endpoint format: '{}'. Expected formats: udp://IP:PORT, tls://HOST:PORT, https://URL, or IP:PORT",
            s
        ))
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
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_udp() {
        let protocol: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
        assert!(matches!(protocol, DnsProtocol::Udp { .. }));
    }

    #[test]
    fn test_parse_udp_default() {
        let protocol: DnsProtocol = "8.8.8.8:53".parse().unwrap();
        assert!(matches!(protocol, DnsProtocol::Udp { .. }));
    }

    #[test]
    fn test_parse_tls() {
        let protocol: DnsProtocol = "tls://1.1.1.1:853".parse().unwrap();
        assert!(matches!(protocol, DnsProtocol::Tls { .. }));
    }

    #[test]
    fn test_parse_tls_hostname() {
        // TLS with hostname should work (uses placeholder IP)
        let protocol: DnsProtocol = "tls://dns.google:853".parse().unwrap();
        assert!(matches!(protocol, DnsProtocol::Tls { .. }));

        // Check hostname is preserved
        if let DnsProtocol::Tls { hostname, addr } = protocol {
            assert_eq!(hostname, "dns.google");
            assert_eq!(addr.port(), 853);
        } else {
            panic!("Expected Tls variant");
        }
    }

    #[test]
    fn test_parse_https() {
        let protocol: DnsProtocol = "https://1.1.1.1/dns-query".parse().unwrap();
        assert!(matches!(protocol, DnsProtocol::Https { .. }));
    }

    #[test]
    fn test_protocol_name() {
        let udp: DnsProtocol = "udp://8.8.8.8:53".parse().unwrap();
        assert_eq!(udp.protocol_name(), "UDP");

        let tls: DnsProtocol = "tls://1.1.1.1:853".parse().unwrap();
        assert_eq!(tls.protocol_name(), "TLS");
    }
}
