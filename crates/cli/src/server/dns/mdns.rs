use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Standard mDNS port (RFC 6762).
const MDNS_PORT: u16 = 5353;
/// IPv4 mDNS multicast group (RFC 6762).
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// Build a non-blocking IPv4 UDP socket bound to `bind`, with
/// `SO_REUSEADDR`/`SO_REUSEPORT` set so it can coexist with a host
/// avahi/mDNSResponder already bound to 5353.
fn build_mdns_socket(bind: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&bind.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Passive mDNS listener: binds UDP 5353, joins the mDNS multicast group, and
/// logs the datagrams it receives. Parsing announcements into device names and
/// populating the query log is a follow-up.
///
/// Non-fatal by design: if the socket cannot be created (e.g. the port is held
/// without address reuse) it warns and returns, so the rest of the server keeps
/// running. Bind to `0.0.0.0` (not the configured `bind_address`) so multicast
/// reception is robust.
pub async fn start_mdns_listener() -> anyhow::Result<()> {
    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT));

    let socket = match build_mdns_socket(bind) {
        Ok(socket) => socket,
        Err(e) => {
            warn!(error = %e, %bind, "mDNS listener could not bind; mDNS disabled for this run");
            return Ok(());
        }
    };

    if let Err(e) = socket.join_multicast_v4(MDNS_GROUP, Ipv4Addr::UNSPECIFIED) {
        warn!(
            error = %e,
            group = %MDNS_GROUP,
            "mDNS listener bound but could not join the multicast group; only unicast traffic will be seen"
        );
    }

    info!(%bind, group = %MDNS_GROUP, "mDNS listener active");

    let mut buf = [0u8; 4096];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => debug!(bytes = len, %src, "mDNS datagram received"),
            Err(e) => {
                // A persistent recv error (e.g. an ICMP port-unreachable surfaced
                // as ECONNREFUSED) must not turn this into a hot, log-flooding
                // loop. Back off briefly and keep listening through transient ones.
                warn!(error = %e, "mDNS receive error; backing off");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn build_mdns_socket_binds_and_receives_unicast() {
        // Ephemeral loopback port — never 5353, which ingests real LAN mDNS chatter.
        let listener = build_mdns_socket(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .expect("mDNS socket should bind on an ephemeral loopback port");
        let addr = listener.local_addr().unwrap();

        let sender = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        sender.send_to(b"hello-mdns", addr).await.unwrap();

        let mut buf = [0u8; 64];
        let (len, _src) = listener.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"hello-mdns");
    }
}
