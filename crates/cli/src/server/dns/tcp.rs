use super::connection_limiter::{ConnectionGuard, ConnectionLimiter};
use super::pktinfo;
use bytes::Buf;
use ferrous_dns_domain::ClientProtocol;
use ferrous_dns_infrastructure::dns::proxy_protocol::{
    read_proxy_v2_client_ip, ProxyProtocolError,
};
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, warn};

pub(super) fn create_tcp_listener(
    domain: Domain,
    socket_addr: SocketAddr,
) -> anyhow::Result<TcpListener> {
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if socket_addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&socket_addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

pub(super) async fn run_tcp_worker(
    listener: Arc<TcpListener>,
    handler: Arc<DnsServerHandler>,
    proxy_protocol_enabled: bool,
    conn_limiter: ConnectionLimiter,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                // The dual-stack listener reports IPv4 peers as `::ffff:a.b.c.d`;
                // normalise so limits, groups, and logs see real IPv4.
                let peer_addr = pktinfo::unmap_socket_addr(peer_addr);
                let guard = match conn_limiter.try_acquire(peer_addr.ip()) {
                    Some(g) => g,
                    None => {
                        debug!(client = %peer_addr, "TCP connection rejected: per-IP limit");
                        drop(stream);
                        continue;
                    }
                };
                tokio::spawn(handle_tcp_connection(
                    stream,
                    peer_addr,
                    handler.clone(),
                    proxy_protocol_enabled,
                    guard,
                ));
            }
            Err(e) => {
                error!(error = %e, "TCP DNS accept error");
            }
        }
    }
}

async fn handle_tcp_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    handler: Arc<DnsServerHandler>,
    proxy_protocol_enabled: bool,
    _guard: ConnectionGuard,
) {
    debug!(client = %peer_addr, "TCP DNS connection accepted");

    // Pipelined answers must not wait for the ACK of the previous one (Nagle).
    if let Err(e) = stream.set_nodelay(true) {
        warn!(client = %peer_addr, error = %e, "Failed to set TCP_NODELAY for TCP DNS");
    }

    let client_ip = if proxy_protocol_enabled {
        match tokio::time::timeout(
            Duration::from_secs(5),
            read_proxy_v2_client_ip(&mut stream, peer_addr.ip()),
        )
        .await
        {
            Ok(Ok(ip)) => ip,
            Ok(Err(ProxyProtocolError::Io(e))) => {
                warn!(client = %peer_addr, error = %e, "TCP DNS PROXY Protocol I/O error");
                return;
            }
            Ok(Err(e)) => {
                warn!(client = %peer_addr, error = %e, "TCP DNS PROXY Protocol v2 header invalid, closing connection");
                return;
            }
            Err(_) => {
                warn!(client = %peer_addr, "TCP DNS PROXY Protocol header read timed out, closing connection");
                return;
            }
        }
    } else {
        peer_addr.ip()
    };

    loop {
        let mut len_buf = [0u8; 2];
        if stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }

        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            break;
        }

        let mut dns_buf = vec![0u8; msg_len];
        if stream.read_exact(&mut dns_buf).await.is_err() {
            break;
        }

        if let Some(resp) = handler
            .handle_raw_udp_fallback(&dns_buf, client_ip, ClientProtocol::Tcp)
            .await
        {
            if write_framed(&mut stream, &resp).await.is_err() {
                break;
            }
        }
    }

    debug!(client = %peer_addr, "TCP DNS connection closed");
}

/// Writes an RFC 1035 §4.2.2 length-prefixed message in one vectored write,
/// so the prefix and payload leave in one segment (or one TLS record).
pub(super) async fn write_framed<S>(stream: &mut S, message: &[u8]) -> std::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let prefix = (message.len() as u16).to_be_bytes();
    stream
        .write_all_buf(&mut Buf::chain(&prefix[..], message))
        .await
}
