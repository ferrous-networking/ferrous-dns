use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};

/// Whether this host has a route to `addr`. Connecting a UDP socket sends
/// nothing: the kernel only picks a route and a source address, as
/// getaddrinfo does for `AI_ADDRCONFIG` and the RFC 6724 sort. In a container
/// without IPv6 that fails with `EADDRNOTAVAIL` or `ENETUNREACH`, and on a
/// kernel without IPv6 the socket itself fails with `EAFNOSUPPORT`. Any other
/// error counts as a route, so the health check gets to decide.
pub fn has_route(addr: SocketAddr) -> bool {
    let local: SocketAddr = match addr {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = match UdpSocket::bind(local) {
        Ok(socket) => socket,
        Err(e) => return e.raw_os_error() != Some(libc::EAFNOSUPPORT),
    };
    match socket.connect(addr) {
        Ok(()) => true,
        Err(e) => !matches!(
            e.kind(),
            ErrorKind::AddrNotAvailable
                | ErrorKind::NetworkUnreachable
                | ErrorKind::HostUnreachable
        ),
    }
}
