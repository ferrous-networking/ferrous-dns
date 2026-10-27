use ferrous_dns_application::use_cases::RecordMdnsHostnamesUseCase;
use ferrous_dns_infrastructure::system::hostnames_from_mdns;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, info, warn};

/// Standard mDNS port (RFC 6762).
const MDNS_PORT: u16 = 5353;
/// IPv4 mDNS multicast group (RFC 6762).
const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The largest mDNS datagram a responder may send (RFC 6762 §17).
const MAX_DATAGRAM: usize = 9000;

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
/// names clients after the host names their devices announce. It never sends.
///
/// Non-fatal by design: if the socket cannot be created (e.g. the port is held
/// without address reuse) it warns and returns, so the rest of the server keeps
/// running. Bind to `0.0.0.0` (not the configured `bind_address`) so multicast
/// reception is robust. The AAAA records a device announces arrive in the same
/// IPv4 datagrams, so the IPv6 group is not joined.
pub async fn start_mdns_listener(recorder: Arc<RecordMdnsHostnamesUseCase>) {
    let bind = SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT));

    let socket = match build_mdns_socket(bind) {
        Ok(socket) => socket,
        Err(e) => {
            warn!(error = %e, %bind, "mDNS listener could not bind; mDNS disabled for this run");
            return;
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
    run_mdns_listener(socket, recorder).await;
}

async fn run_mdns_listener(socket: UdpSocket, recorder: Arc<RecordMdnsHostnamesUseCase>) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src)) => {
                let names = hostnames_from_mdns(&buf[..len], src.ip());
                if names.is_empty() {
                    continue;
                }
                debug!(%src, ?names, "mDNS host names announced");
                if let Err(e) = recorder.execute(&names).await {
                    warn!(error = %e, %src, "Could not record mDNS host names");
                }
            }
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
    use ferrous_dns_application::ports::ClientRepository;
    use ferrous_dns_domain::config::DatabaseConfig;
    use ferrous_dns_infrastructure::repositories::client_repository::SqliteClientRepository;
    use sqlx::sqlite::SqlitePoolOptions;
    use std::net::IpAddr;

    /// An mDNS response announcing `owner` at `ip`, cache-flush class and all.
    fn announcement(owner: &str, ip: Ipv4Addr) -> Vec<u8> {
        let mut packet = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        for label in owner.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0, 1, 0x80, 1, 0, 0, 0, 120, 0, 4]);
        packet.extend_from_slice(&ip.octets());
        packet
    }

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

    #[tokio::test]
    async fn an_announcement_names_the_client_that_sent_it() {
        let pool = SqlitePoolOptions::new()
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::migrate!("../../migrations").run(&pool).await.unwrap();
        let repo = Arc::new(SqliteClientRepository::new(
            pool,
            &DatabaseConfig::default(),
        ));
        let client = IpAddr::V4(Ipv4Addr::LOCALHOST);
        repo.get_or_create(client).await.unwrap();

        // Ephemeral loopback port — never 5353, which ingests real LAN mDNS chatter.
        let listener = build_mdns_socket(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
        let addr = listener.local_addr().unwrap();
        let recorder = Arc::new(RecordMdnsHostnamesUseCase::new(repo.clone()));
        tokio::spawn(run_mdns_listener(listener, recorder));

        let sender = UdpSocket::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        sender.send_to(b"not dns", addr).await.unwrap();
        sender
            .send_to(&announcement("test-box.local", Ipv4Addr::LOCALHOST), addr)
            .await
            .unwrap();

        for _ in 0..100 {
            let named = repo
                .get_by_ip(client)
                .await
                .unwrap()
                .and_then(|c| c.hostname);
            if named.as_deref() == Some("test-box") {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the announcement never named the client");
    }
}
