use ferrous_dns_infrastructure::dns::fast_path;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use ferrous_dns_infrastructure::dns::wire_response;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tracing::error;

use super::pktinfo;

pub(super) fn create_udp_socket(
    domain: Domain,
    socket_addr: SocketAddr,
) -> anyhow::Result<AsyncFd<std::net::UdpSocket>> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if socket_addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.set_recv_buffer_size(512 * 1024)?;
    socket.set_send_buffer_size(512 * 1024)?;
    socket.bind(&socket_addr.into())?;
    pktinfo::enable_pktinfo(&socket);
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    Ok(AsyncFd::with_interest(
        std_socket,
        Interest::READABLE | Interest::WRITABLE,
    )?)
}

pub(super) async fn run_udp_worker(
    socket: Arc<AsyncFd<std::net::UdpSocket>>,
    handler: Arc<DnsServerHandler>,
    worker_id: usize,
) {
    let mut recv_buf = [0u8; 4096];

    loop {
        let mut guard = match socket.readable().await {
            Ok(g) => g,
            Err(_) => break,
        };

        loop {
            match pktinfo::try_recv_with_pktinfo(socket.get_ref(), &mut recv_buf) {
                Ok((n, from, dst_ip)) => {
                    let query_buf = &recv_buf[..n];
                    let client_ip = from.ip();

                    if let Some(fast_query) = fast_path::parse_query(query_buf) {
                        if let Some((addresses, ttl)) = handler.try_fast_path(
                            fast_query.domain(),
                            fast_query.record_type,
                            client_ip,
                        ) {
                            if let Some((wire, wire_len)) = wire_response::build_cache_hit_response(
                                &fast_query,
                                query_buf,
                                &addresses,
                                ttl,
                            ) {
                                let _ = pktinfo::try_send_with_src_ip(
                                    socket.get_ref(),
                                    &wire[..wire_len],
                                    from,
                                    dst_ip,
                                );
                                continue;
                            }
                        }
                    }

                    let handler_clone = handler.clone();
                    let socket_clone = socket.clone();
                    let owned_buf: Arc<[u8]> = Arc::from(query_buf);
                    tokio::spawn(async move {
                        if let Some(response) = handler_clone
                            .handle_raw_udp_fallback(&owned_buf, client_ip)
                            .await
                        {
                            let _ = pktinfo::try_send_with_src_ip(
                                socket_clone.get_ref(),
                                &response,
                                from,
                                dst_ip,
                            );
                        }
                    });
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    error!(worker = worker_id, error = %e, "UDP recv error");
                    guard.clear_ready();
                    break;
                }
            }
        }
    }
}
