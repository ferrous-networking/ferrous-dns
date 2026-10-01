use ferrous_dns_application::drop_counter::DropCounter;
use ferrous_dns_domain::ClientProtocol;
use ferrous_dns_infrastructure::dns::cache::coarse_clock::coarse_now_secs;
use ferrous_dns_infrastructure::dns::fast_path::{self, FastPathKind};
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use ferrous_dns_infrastructure::dns::wire_response;
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

/// Admission shared by every UDP worker for queries that leave the inline
/// cache path. It bounds the spawned tasks, and sheds before the copy and the
/// spawn; queries that wait on an upstream are bounded in the use case.
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

/// Binds one SO_REUSEPORT worker socket, always AF_INET6 with `only_v6` off:
/// an IPv4 `bind` is mapped to `::ffff:a.b.c.d` so the pktinfo path can
/// assume sockaddr_in6 / in6_pktinfo, and `[::]` serves both families.
pub(super) fn create_udp_socket(bind: SocketAddr) -> anyhow::Result<AsyncFd<std::net::UdpSocket>> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(false)?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    // 4 MB buffers — accommodate ~128 full batches of 64 × 512-byte packets.
    socket.set_recv_buffer_size(4 * 1024 * 1024)?;
    socket.set_send_buffer_size(4 * 1024 * 1024)?;
    socket.bind(&pktinfo::v6_mapped_bind_addr(bind).into())?;
    // Without it every reply would silently leave from a kernel-chosen address.
    pktinfo::enable_pktinfo(&socket)?;

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

#[cfg(target_os = "linux")]
async fn run_udp_worker_batch(
    socket: Arc<AsyncFd<std::net::UdpSocket>>,
    handler: Arc<DnsServerHandler>,
    admission: Arc<FallbackAdmission>,
    worker_id: usize,
) {
    let mut batch = pktinfo::RecvBatch::new();
    let mut send_batch = pktinfo::SendBatch::new();
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
            let n = match batch.recv(fd) {
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

            pending_wire.clear();
            for i in 0..n {
                let msg = batch.get_msg(i);
                let client_ip = msg.src.ip();

                if let Some(fast_query) =
                    fast_path::parse_query(msg.data).filter(|q| !q.wants_dnssec)
                {
                    match fast_query.kind {
                        FastPathKind::IpAddress => {
                            // Encoded straight into the sendmmsg buffer.
                            let staged = handler.try_fast_path(
                                fast_query.domain(),
                                fast_query.record_type,
                                client_ip,
                                ClientProtocol::Udp,
                                |addresses, ttl| {
                                    send_batch
                                        .stage(msg.src, msg.dst_ip, |out| {
                                            wire_response::build_cache_hit_response(
                                                &fast_query,
                                                msg.data,
                                                addresses,
                                                ttl,
                                                out,
                                            )
                                        })
                                        .then_some(())
                                },
                            );
                            if staged.is_some() {
                                continue;
                            }
                        }
                        FastPathKind::WireData => {
                            if let Some(patched) = handler.try_fast_path_wire(
                                &fast_query,
                                msg.data,
                                client_ip,
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

            if let Err(e) = send_batch.flush(fd) {
                if e.kind() != io::ErrorKind::WouldBlock {
                    error!(worker = worker_id, error = %e, "UDP sendmmsg error");
                }
            }

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

            // A short batch drained the queue as of that syscall, so skip the
            // recvmmsg that would only return EAGAIN. Safe under edge
            // triggering: a datagram arriving after it re-arms epoll, and
            // clear_ready is a no-op if the driver has already seen one.
            if n < pktinfo::BATCH_SIZE {
                guard.clear_ready();
                break;
            }
        }
    }
}

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
                                let sent = handler.try_fast_path(
                                    fast_query.domain(),
                                    fast_query.record_type,
                                    client_ip,
                                    ClientProtocol::Udp,
                                    |addresses, ttl| {
                                        let mut wire = [0u8; wire_response::RESPONSE_BUF_LEN];
                                        let wire_len = wire_response::build_cache_hit_response(
                                            &fast_query,
                                            query_buf,
                                            addresses,
                                            ttl,
                                            &mut wire,
                                        )?;
                                        let _ = pktinfo::try_send_with_src_ip(
                                            socket.get_ref(),
                                            &wire[..wire_len],
                                            from,
                                            dst_ip,
                                        );
                                        Some(())
                                    },
                                );
                                if sent.is_some() {
                                    continue;
                                }
                            }
                            FastPathKind::WireData => {
                                if let Some(patched) = handler.try_fast_path_wire(
                                    &fast_query,
                                    query_buf,
                                    client_ip,
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
    use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
    use ferrous_dns_domain::{DnsQuery, DomainError};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::net::UdpSocket;
    use tokio::sync::Notify;

    struct GatedResolver {
        entered: Notify,
        release: Semaphore,
        resolved: AtomicUsize,
    }

    impl GatedResolver {
        fn new() -> Self {
            Self {
                entered: Notify::new(),
                release: Semaphore::new(0),
                resolved: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl DnsResolver for GatedResolver {
        async fn resolve(&self, _: &DnsQuery) -> Result<DnsResolution, DomainError> {
            self.resolved.fetch_add(1, Ordering::Relaxed);
            self.entered.notify_one();
            self.release.acquire().await.unwrap().forget();
            Ok(DnsResolution::new(
                vec![IpAddr::from([192, 0, 2, 1])],
                false,
            ))
        }

        fn try_cache(&self, query: &DnsQuery) -> Option<DnsResolution> {
            match query.domain.as_ref() {
                "cached.example" => {
                    Some(DnsResolution::new(vec![IpAddr::from([192, 0, 2, 1])], true))
                }
                // A negative entry: a hit without response data.
                "nx.example" => Some(DnsResolution::new(vec![], true)),
                _ => None,
            }
        }
    }

    fn with_id(id: u16, mut packet: Vec<u8>) -> Vec<u8> {
        packet[..2].copy_from_slice(&id.to_be_bytes());
        packet
    }

    /// The response's ID and RCODE.
    fn id_and_rcode(response: &[u8]) -> (u16, u8) {
        (
            u16::from_be_bytes([response[0], response[1]]),
            response[3] & 0x0f,
        )
    }

    #[tokio::test]
    async fn saturated_misses_are_dropped_without_delaying_cache_hits() {
        // Mirror the default deployment: an IPv4 bind on a dual-stack AF_INET6 socket.
        if !test_support::dual_stack_loopback_available() {
            eprintln!("skipping: no dual-stack loopback available");
            return;
        }
        let resolver = Arc::new(GatedResolver::new());
        let socket = Arc::new(create_udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
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

    /// Issue #239: answers that never wait on an upstream (a blocked name, a
    /// DO=1 cache hit, a cached NXDOMAIN) stay serviceable while misses hold
    /// every upstream slot; a new miss is still shed.
    #[tokio::test]
    async fn local_answers_are_served_while_misses_hold_the_upstream_budget() {
        if !test_support::dual_stack_loopback_available() {
            eprintln!("skipping: no dual-stack loopback available");
            return;
        }
        let resolver = Arc::new(GatedResolver::new());
        let socket = Arc::new(create_udp_socket("127.0.0.1:0".parse().unwrap()).unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client
            .connect(test_support::unmap_addr(
                socket.get_ref().local_addr().unwrap(),
            ))
            .await
            .unwrap();
        // One upstream slot, and room for the burst below in the listener's budget.
        let use_case = HandleDnsQueryUseCase::new(
            resolver.clone(),
            Arc::new(test_support::BlockOneFilter("blocked.example")),
            Arc::new(test_support::NoopQueryLog),
        )
        .with_upstream_limit(1);
        let worker = tokio::spawn(run_udp_worker(
            socket,
            test_support::handler_with_use_case(use_case),
            Arc::new(FallbackAdmission::new(8)),
            0,
        ));

        let query = |id, name| with_id(id, test_support::build_a_query(name));
        let exercise = async {
            client.send(&query(1, "slow.example")).await.unwrap();
            resolver.entered.notified().await;
            client.send(&query(2, "shed.example")).await.unwrap();
            client.send(&query(3, "blocked.example")).await.unwrap();
            client
                .send(&with_id(
                    4,
                    test_support::build_a_query_with_do("cached.example"),
                ))
                .await
                .unwrap();
            client.send(&query(5, "nx.example")).await.unwrap();

            let mut response = [0; 512];
            let mut answered = Vec::new();
            for _ in 0..3 {
                let len = client.recv(&mut response).await.unwrap();
                answered.push(id_and_rcode(&response[..len]));
            }
            answered.sort_unstable();
            // NOERROR for the blocked name (null-IP answer) and the DO=1 hit,
            // NXDOMAIN for the negative entry.
            assert_eq!(answered, [(3, 0), (4, 0), (5, 3)]);
            // The new miss never reached the resolver.
            assert_eq!(resolver.resolved.load(Ordering::Relaxed), 1);

            resolver.release.add_permits(1);
            let len = client.recv(&mut response).await.unwrap();
            assert_eq!(id_and_rcode(&response[..len]), (1, 0));

            client.send(&query(6, "next.example")).await.unwrap();
            resolver.entered.notified().await;
            resolver.release.add_permits(1);
            let len = client.recv(&mut response).await.unwrap();
            assert_eq!(id_and_rcode(&response[..len]), (6, 0));
        };
        let result = tokio::time::timeout(Duration::from_secs(5), exercise).await;
        worker.abort();
        result.unwrap();
    }
}
