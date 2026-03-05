use ferrous_dns_infrastructure::dns::proxy_protocol::{
    read_proxy_v2_client_ip, ProxyProtocolError,
};
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                tokio::spawn(handle_tcp_connection(
                    stream,
                    peer_addr,
                    handler.clone(),
                    proxy_protocol_enabled,
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
) {
    debug!(client = %peer_addr, "TCP DNS connection accepted");

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

        if let Some(resp) = handler.handle_raw_udp_fallback(&dns_buf, client_ip).await {
            let resp_len = (resp.len() as u16).to_be_bytes();
            if stream.write_all(&resp_len).await.is_err() {
                break;
            }
            if stream.write_all(&resp).await.is_err() {
                break;
            }
        }
    }

    debug!(client = %peer_addr, "TCP DNS connection closed");
}
