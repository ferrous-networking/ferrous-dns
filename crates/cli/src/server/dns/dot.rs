use super::connection_limiter::{ConnectionGuard, ConnectionLimiter};
use ferrous_dns_infrastructure::dns::proxy_protocol::{
    read_proxy_v2_client_ip, ProxyProtocolError,
};
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

pub fn create_dot_listener(domain: Domain, addr: SocketAddr) -> anyhow::Result<TcpListener> {
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}

pub async fn start_dot_server(
    bind_addr: String,
    handler: Arc<DnsServerHandler>,
    tls_config: Arc<rustls::ServerConfig>,
    num_workers: usize,
    proxy_protocol_enabled: bool,
    dot_conn_limiter: ConnectionLimiter,
) -> anyhow::Result<()> {
    let addr: SocketAddr = bind_addr.parse()?;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let acceptor = TlsAcceptor::from(tls_config);

    info!(bind_address = %addr, "Starting DoT server (DNS-over-TLS, RFC 7858)");

    let listener = Arc::new(create_dot_listener(domain, addr)?);

    let mut handles = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        handles.push(tokio::spawn(run_dot_accept_loop(
            listener.clone(),
            acceptor.clone(),
            handler.clone(),
            proxy_protocol_enabled,
            dot_conn_limiter.clone(),
        )));
    }

    info!("DoT server ready on {}", addr);
    for handle in handles {
        let _ = handle.await;
    }
    Ok(())
}

async fn run_dot_accept_loop(
    listener: Arc<TcpListener>,
    acceptor: TlsAcceptor,
    handler: Arc<DnsServerHandler>,
    proxy_protocol_enabled: bool,
    conn_limiter: ConnectionLimiter,
) {
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let guard = match conn_limiter.try_acquire(peer_addr.ip()) {
                    Some(g) => g,
                    None => {
                        debug!(client = %peer_addr, "DoT connection rejected: per-IP limit");
                        drop(stream);
                        continue;
                    }
                };
                tokio::spawn(handle_dot_connection(
                    stream,
                    peer_addr,
                    acceptor.clone(),
                    handler.clone(),
                    proxy_protocol_enabled,
                    guard,
                ));
            }
            Err(e) => {
                error!(error = %e, "DoT accept error");
            }
        }
    }
}

async fn handle_dot_connection(
    mut stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    handler: Arc<DnsServerHandler>,
    proxy_protocol_enabled: bool,
    _guard: ConnectionGuard,
) {
    debug!(client = %peer_addr, "DoT connection accepted");

    let client_ip = if proxy_protocol_enabled {
        match tokio::time::timeout(
            Duration::from_secs(5),
            read_proxy_v2_client_ip(&mut stream, peer_addr.ip()),
        )
        .await
        {
            Ok(Ok(ip)) => ip,
            Ok(Err(ProxyProtocolError::Io(e))) => {
                warn!(client = %peer_addr, error = %e, "DoT PROXY Protocol I/O error");
                return;
            }
            Ok(Err(e)) => {
                warn!(client = %peer_addr, error = %e, "DoT PROXY Protocol v2 header invalid, closing connection");
                return;
            }
            Err(_) => {
                warn!(client = %peer_addr, "DoT PROXY Protocol header read timed out, closing connection");
                return;
            }
        }
    } else {
        peer_addr.ip()
    };

    let mut tls_stream = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            warn!(client = %peer_addr, error = %e, "DoT TLS handshake failed");
            return;
        }
    };

    loop {
        let mut len_buf = [0u8; 2];
        if tls_stream.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let msg_len = u16::from_be_bytes(len_buf) as usize;
        if msg_len == 0 {
            break;
        }

        let mut dns_buf = vec![0u8; msg_len];
        if tls_stream.read_exact(&mut dns_buf).await.is_err() {
            break;
        }

        if let Some(resp) = handler.handle_raw_udp_fallback(&dns_buf, client_ip).await {
            let resp_len = (resp.len() as u16).to_be_bytes();
            if tls_stream.write_all(&resp_len).await.is_err() {
                break;
            }
            if tls_stream.write_all(&resp).await.is_err() {
                break;
            }
        }
    }

    debug!(client = %peer_addr, "DoT connection closed");
}
