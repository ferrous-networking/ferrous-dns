use ferrous_dns_infrastructure::dns::fast_path;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use ferrous_dns_infrastructure::dns::wire_response;
use hickory_server::ServerFuture;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinSet;
use tracing::{error, info};

pub async fn start_dns_server(bind_addr: String, handler: DnsServerHandler) -> anyhow::Result<()> {
    let socket_addr: SocketAddr = bind_addr.parse()?;
    let domain = if socket_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    let num_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    info!(bind_address = %socket_addr, num_workers, "Starting DNS server with SO_REUSEPORT");

    let handler = Arc::new(handler);
    let mut join_set: JoinSet<()> = JoinSet::new();

    for i in 0..num_workers {
        let udp_socket = Arc::new(create_udp_socket(domain, socket_addr)?);
        let handler_udp = handler.clone();
        join_set.spawn(async move {
            run_udp_worker(udp_socket, handler_udp, i).await;
        });

        let tcp_listener = create_tcp_listener(domain, socket_addr)?;
        let handler_tcp = (*handler).clone();
        join_set.spawn(async move {
            let mut server = ServerFuture::new(handler_tcp);
            server.register_listener(tcp_listener, std::time::Duration::from_secs(10));
            if let Err(e) = server.block_until_done().await {
                error!(worker = i, error = %e, "TCP DNS worker error");
            }
        });
    }

    info!(
        "DNS server ready — {} workers on {}",
        num_workers, socket_addr
    );

    while join_set.join_next().await.is_some() {}
    Ok(())
}

/// Per-worker UDP loop with two code paths:
///
/// **Fast path** (cache hit, A/AAAA, no DNSSEC):
///   `recv_from` → `parse_query` → `try_fast_path` → `build_cache_hit_response` → `send_to`
///   Zero heap allocation. Bypasses Hickory's Name/Record/BinEncoder chain entirely.
///
/// **Fallback** (cache miss, non-A/AAAA, DNSSEC DO bit, blocked, parse error):
///   Spawns a task → `handle_raw_udp_fallback` (full use-case + Hickory serialization).
///   Spawning keeps the recv loop non-blocking.
async fn run_udp_worker(socket: Arc<UdpSocket>, handler: Arc<DnsServerHandler>, worker_id: usize) {
    let mut recv_buf = [0u8; 4096];

    loop {
        let (n, from) = match socket.recv_from(&mut recv_buf).await {
            Ok(x) => x,
            Err(e) => {
                error!(worker = worker_id, error = %e, "UDP recv error");
                continue;
            }
        };

        let query_buf = &recv_buf[..n];
        let client_ip = from.ip();

        if let Some(fast_query) = fast_path::parse_query(query_buf) {
            if let Some((addresses, ttl)) =
                handler.try_fast_path(fast_query.domain(), fast_query.record_type)
            {
                if let Some((wire, wire_len)) =
                    wire_response::build_cache_hit_response(&fast_query, query_buf, &addresses, ttl)
                {
                    let _ = socket.send_to(&wire[..wire_len], from).await;
                    continue;
                }
            }
        }

        let handler_clone = handler.clone();
        let socket_clone = socket.clone();
        let owned_buf = query_buf.to_vec();
        tokio::spawn(async move {
            if let Some(response) = handler_clone
                .handle_raw_udp_fallback(&owned_buf, client_ip)
                .await
            {
                let _ = socket_clone.send_to(&response, from).await;
            }
        });
    }
}

fn create_udp_socket(domain: Domain, socket_addr: SocketAddr) -> anyhow::Result<UdpSocket> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if socket_addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_recv_buffer_size(8 * 1024 * 1024)?;
    socket.set_send_buffer_size(4 * 1024 * 1024)?;
    socket.bind(&socket_addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(UdpSocket::from_std(std_socket)?)
}

fn create_tcp_listener(domain: Domain, socket_addr: SocketAddr) -> anyhow::Result<TcpListener> {
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
