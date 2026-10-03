pub mod connection_limiter;
pub mod doq;
pub mod dot;
mod mdns;
mod pktinfo;
mod tcp;
pub mod tls_config;
mod udp;

pub use mdns::start_mdns_listener;
pub use tcp::bind_tcp_listener;

use connection_limiter::ConnectionLimiter;
use ferrous_dns_application::drop_counter::DropCounter;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::info;

/// Client queries, over every transport, that may wait on an upstream at once.
pub const MAX_UPSTREAM_BOUND_QUERIES: usize = 4096;
/// UDP fallback tasks in flight. The headroom over the upstream budget keeps
/// answers that need no upstream serviceable while that budget is full.
const MAX_IN_FLIGHT_UDP_QUERIES: usize = 2 * MAX_UPSTREAM_BOUND_QUERIES;

/// Starts the Do53 listeners on `bind`: one SO_REUSEPORT UDP socket and TCP
/// listener per worker, each a dual-stack AF_INET6 socket (see `udp` / `tcp`).
/// UDP queries shed for lack of a fallback slot count in `udp_fallback_shed`.
pub async fn start_dns_server(
    bind: SocketAddr,
    handler: DnsServerHandler,
    num_workers: usize,
    proxy_protocol_enabled: bool,
    tcp_conn_limiter: ConnectionLimiter,
    udp_fallback_shed: Arc<DropCounter>,
) -> anyhow::Result<()> {
    info!(bind_address = %bind, num_workers, "Starting DNS server with SO_REUSEPORT");

    let handler = Arc::new(handler);
    let udp_admission = Arc::new(udp::FallbackAdmission::new(
        MAX_IN_FLIGHT_UDP_QUERIES,
        udp_fallback_shed,
    ));
    let mut join_set: JoinSet<()> = JoinSet::new();

    for i in 0..num_workers {
        let udp_socket = Arc::new(udp::create_udp_socket(bind)?);
        let handler_udp = handler.clone();
        let admission = udp_admission.clone();
        join_set.spawn(async move {
            udp::run_udp_worker(udp_socket, handler_udp, admission, i).await;
        });

        let tcp_listener = Arc::new(tcp::bind_tcp_listener(bind)?);
        let handler_tcp = handler.clone();
        let tcp_limiter = tcp_conn_limiter.clone();
        join_set.spawn(async move {
            tcp::run_tcp_worker(
                tcp_listener,
                handler_tcp,
                proxy_protocol_enabled,
                tcp_limiter,
            )
            .await;
        });
    }

    info!("DNS server ready — {} workers on {}", num_workers, bind);

    while join_set.join_next().await.is_some() {}
    Ok(())
}
