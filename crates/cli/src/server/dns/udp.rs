use ferrous_dns_infrastructure::dns::fast_path::{self, FastPathKind};
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use ferrous_dns_infrastructure::dns::wire_response;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tracing::error;

use super::pktinfo;

pub(super) fn create_udp_socket(
    domain: Domain,
    socket_addr: SocketAddr,
    cpu_id: usize,
) -> anyhow::Result<AsyncFd<std::net::UdpSocket>> {
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if socket_addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    // 4 MB buffers — accommodate ~128 full batches of 64 × 512-byte packets.
    socket.set_recv_buffer_size(4 * 1024 * 1024)?;
    socket.set_send_buffer_size(4 * 1024 * 1024)?;
    socket.bind(&socket_addr.into())?;
    pktinfo::enable_pktinfo(&socket);

    // SO_BUSY_POLL + SO_INCOMING_CPU: perf hints, Linux only.
    #[cfg(target_os = "linux")]
    pktinfo::set_udp_perf_opts(socket.as_raw_fd(), cpu_id);

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
    #[cfg(target_os = "linux")]
    run_udp_worker_batch(socket, handler, worker_id).await;

    #[cfg(not(target_os = "linux"))]
    run_udp_worker_single(socket, handler, worker_id).await;
}

// ── Linux: recvmmsg / sendmmsg batch path ─────────────────────────────────────

#[cfg(target_os = "linux")]
async fn run_udp_worker_batch(
    socket: Arc<AsyncFd<std::net::UdpSocket>>,
    handler: Arc<DnsServerHandler>,
    worker_id: usize,
) {
    // Pre-allocate batch state once per worker — reused across all iterations.
    let mut batch = pktinfo::RecvBatch::new(pktinfo::BATCH_SIZE);
    let mut send_batch = pktinfo::SendBatch::new(pktinfo::BATCH_SIZE);
    // Pre-allocate response queues — cleared between batches, never reallocated.
    let mut pending: Vec<pktinfo::PendingResponse> = Vec::with_capacity(pktinfo::BATCH_SIZE);
    let mut pending_wire: Vec<pktinfo::PendingWireResponse> =
        Vec::with_capacity(pktinfo::BATCH_SIZE);

    let fd = socket.get_ref().as_raw_fd();

    loop {
        let mut guard = match socket.readable().await {
            Ok(g) => g,
            Err(_) => break,
        };

        loop {
            let n = match pktinfo::recv_batch(fd, &mut batch) {
                Ok(0) => {
                    guard.clear_ready();
                    break;
                }
                Ok(n) => n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    guard.clear_ready();
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    error!(worker = worker_id, error = %e, "UDP recvmmsg error");
                    guard.clear_ready();
                    break;
                }
            };

            // Process each received packet in the batch.
            pending.clear();
            pending_wire.clear();
            for i in 0..n {
                let msg = batch.get_msg(i);
                let client_ip = msg.src.ip();

                if let Some(fast_query) = fast_path::parse_query(msg.data) {
                    match fast_query.kind {
                        FastPathKind::IpAddress => {
                            if let Some((addresses, ttl)) = handler.try_fast_path(
                                fast_query.domain(),
                                fast_query.record_type,
                                client_ip,
                            ) {
                                if let Some((wire, wire_len)) =
                                    wire_response::build_cache_hit_response(
                                        &fast_query,
                                        msg.data,
                                        &addresses,
                                        ttl,
                                    )
                                {
                                    // Fast path: inline wire buf — zero extra heap allocation.
                                    pending.push(pktinfo::PendingResponse {
                                        wire,
                                        len: wire_len,
                                        to: msg.src,
                                        src_ip: msg.dst_ip,
                                    });
                                    continue;
                                }
                            }
                        }
                        FastPathKind::WireData => {
                            if let Some((wire_bytes, _ttl)) = handler.try_fast_path_wire(
                                fast_query.domain(),
                                fast_query.record_type,
                                client_ip,
                            ) {
                                if let Some(patched) =
                                    wire_response::patch_wire_id(&wire_bytes, fast_query.id)
                                {
                                    pending_wire.push(pktinfo::PendingWireResponse {
                                        data: patched,
                                        to: msg.src,
                                        src_ip: msg.dst_ip,
                                    });
                                    continue;
                                }
                            }
                        }
                    }
                }

                // Cache miss — spawn async task (slow path).
                let handler_clone = handler.clone();
                let socket_clone = socket.clone();
                let owned_buf: Arc<[u8]> = Arc::from(msg.data);
                let from = msg.src;
                let dst_ip = msg.dst_ip;
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

            // Flush A/AAAA responses via sendmmsg (pre-allocated, single syscall).
            if !pending.is_empty() {
                if let Err(e) = send_batch.send(fd, &pending) {
                    if e.kind() != io::ErrorKind::WouldBlock {
                        error!(worker = worker_id, error = %e, "UDP sendmmsg error");
                    }
                }
            }

            // Flush wire-data responses (MX, TXT, NS, etc.) individually.
            for resp in &pending_wire {
                let _ = pktinfo::try_send_with_src_ip(
                    socket.get_ref(),
                    &resp.data,
                    resp.to,
                    resp.src_ip,
                );
            }
        }
    }
}

// ── Non-Linux: single recvmsg / sendmsg fallback ──────────────────────────────

#[cfg(not(target_os = "linux"))]
async fn run_udp_worker_single(
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
                        match fast_query.kind {
                            FastPathKind::IpAddress => {
                                if let Some((addresses, ttl)) = handler.try_fast_path(
                                    fast_query.domain(),
                                    fast_query.record_type,
                                    client_ip,
                                ) {
                                    if let Some((wire, wire_len)) =
                                        wire_response::build_cache_hit_response(
                                            &fast_query,
                                            query_buf,
                                            &addresses,
                                            ttl,
                                        )
                                    {
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
                            FastPathKind::WireData => {
                                if let Some((wire_bytes, _ttl)) = handler.try_fast_path_wire(
                                    fast_query.domain(),
                                    fast_query.record_type,
                                    client_ip,
                                ) {
                                    if let Some(patched) =
                                        wire_response::patch_wire_id(&wire_bytes, fast_query.id)
                                    {
                                        let _ = pktinfo::try_send_with_src_ip(
                                            socket.get_ref(),
                                            &patched,
                                            from,
                                            dst_ip,
                                        );
                                        continue;
                                    }
                                }
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
