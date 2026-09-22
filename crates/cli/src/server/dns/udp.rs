use ferrous_dns_domain::ClientProtocol;
use ferrous_dns_infrastructure::dns::cache::coarse_clock::coarse_now_secs;
use ferrous_dns_infrastructure::dns::fast_path::{self, FastPathKind};
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use ferrous_dns_infrastructure::dns::wire_response;
use ferrous_dns_infrastructure::drop_counter::DropCounter;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::io::Interest;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::{error, warn};

use super::pktinfo;

const PACKETS_BEFORE_YIELD: usize = 256;

/// Admission shared by every listener for queries that leave the inline cache path.
pub(super) struct FallbackAdmission {
    slots: Arc<Semaphore>,
    shed: DropCounter,
}

impl FallbackAdmission {
    pub(super) fn new(limit: usize) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(limit)),
            shed: DropCounter::new(),
        }
    }

    fn try_admit(&self) -> Option<OwnedSemaphorePermit> {
        let permit = Arc::clone(&self.slots).try_acquire_owned().ok();
        if permit.is_none() {
            // Distinguishes deliberate shedding from packet loss for operators.
            if let Some(report) = self.shed.record(coarse_now_secs()) {
                warn!(
                    shed = report.since_last,
                    total_shed = report.total,
                    "UDP fallback capacity exhausted; queries dropped"
                );
            }
        }
        permit
    }
}

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
    // 4 MB buffers — accommodate ~128 full batches of 64 × 512-byte packets.
    socket.set_recv_buffer_size(4 * 1024 * 1024)?;
    socket.set_send_buffer_size(4 * 1024 * 1024)?;
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
    admission: Arc<FallbackAdmission>,
    worker_id: usize,
) {
    #[cfg(target_os = "linux")]
    run_udp_worker_batch(socket, handler, admission, worker_id).await;

    #[cfg(not(target_os = "linux"))]
    run_udp_worker_single(socket, handler, admission, worker_id).await;
}

fn spawn_fallback(
    socket: &Arc<AsyncFd<std::net::UdpSocket>>,
    handler: &Arc<DnsServerHandler>,
    admission: &FallbackAdmission,
    query: &[u8],
    peer: SocketAddr,
    source: IpAddr,
) {
    // Shed UDP overload before allocating a packet or creating a waiting task.
    let Some(permit) = admission.try_admit() else {
        return;
    };
    let query = query.to_vec();
    let handler = handler.clone();
    let socket = socket.clone();
    tokio::spawn(async move {
        let _permit = permit;
        if let Some(response) = handler
            .handle_raw_udp_fallback(&query, peer.ip(), ClientProtocol::Udp)
            .await
        {
            let _ = pktinfo::try_send_with_src_ip(socket.get_ref(), &response, peer, source);
        }
    });
}

// ── Linux: recvmmsg / sendmmsg batch path ─────────────────────────────────────

#[cfg(target_os = "linux")]
async fn run_udp_worker_batch(
    socket: Arc<AsyncFd<std::net::UdpSocket>>,
    handler: Arc<DnsServerHandler>,
    admission: Arc<FallbackAdmission>,
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
    let mut processed = 0;

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

                if let Some(fast_query) =
                    fast_path::parse_query(msg.data).filter(|q| !q.wants_dnssec)
                {
                    match fast_query.kind {
                        FastPathKind::IpAddress => {
                            if let Some((addresses, ttl)) = handler.try_fast_path(
                                fast_query.domain(),
                                fast_query.record_type,
                                client_ip,
                                ClientProtocol::Udp,
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
                            if let Some((patched, _ttl)) = handler.try_fast_path_wire(
                                fast_query.domain(),
                                fast_query.record_type,
                                client_ip,
                                fast_query.id,
                                fast_query.client_max_size,
                                ClientProtocol::Udp,
                            ) {
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

                spawn_fallback(&socket, &handler, &admission, msg.data, msg.src, msg.dst_ip);
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

            // Raw recvmmsg bypasses Tokio's cooperative I/O budget.
            processed += n;
            if processed >= PACKETS_BEFORE_YIELD {
                tokio::task::yield_now().await;
                processed = 0;
            }
        }
    }
}

// ── Non-Linux: single recvmsg / sendmsg fallback ──────────────────────────────

#[cfg(not(target_os = "linux"))]
async fn run_udp_worker_single(
    socket: Arc<AsyncFd<std::net::UdpSocket>>,
    handler: Arc<DnsServerHandler>,
    admission: Arc<FallbackAdmission>,
    worker_id: usize,
) {
    let mut recv_buf = [0u8; 4096];

    loop {
        let mut guard = match socket.readable().await {
            Ok(g) => g,
            Err(_) => break,
        };

        let mut remaining = PACKETS_BEFORE_YIELD;
        loop {
            if remaining == 0 {
                tokio::task::yield_now().await;
                remaining = PACKETS_BEFORE_YIELD;
            }
            remaining -= 1;
            match pktinfo::try_recv_with_pktinfo(socket.get_ref(), &mut recv_buf) {
                Ok((n, from, dst_ip)) => {
                    let query_buf = &recv_buf[..n];
                    let client_ip = from.ip();

                    if let Some(fast_query) =
                        fast_path::parse_query(query_buf).filter(|q| !q.wants_dnssec)
                    {
                        match fast_query.kind {
                            FastPathKind::IpAddress => {
                                if let Some((addresses, ttl)) = handler.try_fast_path(
                                    fast_query.domain(),
                                    fast_query.record_type,
                                    client_ip,
                                    ClientProtocol::Udp,
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
                                if let Some((patched, _ttl)) = handler.try_fast_path_wire(
                                    fast_query.domain(),
                                    fast_query.record_type,
                                    client_ip,
                                    fast_query.id,
                                    fast_query.client_max_size,
                                    ClientProtocol::Udp,
                                ) {
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

                    spawn_fallback(&socket, &handler, &admission, query_buf, from, dst_ip);
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

#[cfg(test)]
#[path = "../../../tests/common/mod.rs"]
mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use ferrous_dns_application::ports::{DnsResolution, DnsResolver};
    use ferrous_dns_domain::{DnsQuery, DomainError};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::sync::Notify;

    struct GatedResolver {
        entered: Notify,
        release: Semaphore,
    }

    #[async_trait]
    impl DnsResolver for GatedResolver {
        async fn resolve(&self, _: &DnsQuery) -> Result<DnsResolution, DomainError> {
            self.entered.notify_one();
            self.release.acquire().await.unwrap().forget();
            Ok(DnsResolution::new(
                vec![IpAddr::from([192, 0, 2, 1])],
                false,
            ))
        }

        fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
            (query.domain.as_ref() == "cached.example")
                .then(|| DnsResolution::new(vec![IpAddr::from([192, 0, 2, 1])], true))
        }
    }

    #[tokio::test]
    async fn saturated_misses_are_dropped_without_delaying_cache_hits() {
        // Mirror the default deployment: an IPv4 bind on a dual-stack AF_INET6 socket.
        if !test_support::dual_stack_loopback_available() {
            eprintln!("skipping: no dual-stack loopback available");
            return;
        }
        let resolver = Arc::new(GatedResolver {
            entered: Notify::new(),
            release: Semaphore::new(0),
        });
        let bind = pktinfo::v6_mapped_bind_addr("127.0.0.1:0".parse().unwrap());
        let socket = Arc::new(create_udp_socket(Domain::IPV6, bind).unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .connect(test_support::unmap_addr(
                socket.get_ref().local_addr().unwrap(),
            ))
            .await
            .unwrap();
        let worker = tokio::spawn(run_udp_worker(
            socket,
            test_support::handler_with_resolver(resolver.clone()),
            Arc::new(FallbackAdmission::new(1)),
            0,
        ));

        let query = |id: u16, name| {
            let mut packet = test_support::build_a_query(name);
            packet[..2].copy_from_slice(&id.to_be_bytes());
            packet
        };
        let exercise = async {
            client.send(&query(1, "slow.example")).await.unwrap();
            resolver.entered.notified().await;
            client.send(&query(2, "shed.example")).await.unwrap();
            client.send(&query(3, "cached.example")).await.unwrap();
            let mut response = [0; 512];
            client.recv(&mut response).await.unwrap();
            assert_eq!(&response[..2], &3u16.to_be_bytes());

            resolver.release.add_permits(1);
            client.recv(&mut response).await.unwrap();
            assert_eq!(&response[..2], &1u16.to_be_bytes());

            client.send(&query(4, "next.example")).await.unwrap();
            resolver.entered.notified().await;
            resolver.release.add_permits(1);
            client.recv(&mut response).await.unwrap();
            assert_eq!(&response[..2], &4u16.to_be_bytes());
        };
        let result = tokio::time::timeout(Duration::from_secs(5), exercise).await;
        worker.abort();
        result.unwrap();
    }
}
