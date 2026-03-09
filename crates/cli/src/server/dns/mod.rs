pub(crate) mod connection_limiter;
pub mod dot;
mod pktinfo;
mod tcp;
pub mod tls_config;
mod udp;

use connection_limiter::ConnectionLimiter;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use socket2::Domain;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::info;

pub async fn start_dns_server(
    bind_addr: String,
    handler: DnsServerHandler,
    num_workers: usize,
    proxy_protocol_enabled: bool,
    core_ids: Vec<core_affinity::CoreId>,
    tcp_conn_limiter: ConnectionLimiter,
) -> anyhow::Result<()> {
    let socket_addr: SocketAddr = bind_addr.parse()?;
    let domain = if socket_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };

    info!(bind_address = %socket_addr, num_workers, "Starting DNS server with SO_REUSEPORT");

    let handler = Arc::new(handler);
    let mut join_set: JoinSet<()> = JoinSet::new();

    for i in 0..num_workers {
        let cpu_id = if core_ids.is_empty() {
            0
        } else {
            core_ids[i % core_ids.len()].id
        };
        let udp_socket = Arc::new(udp::create_udp_socket(domain, socket_addr, cpu_id)?);
        let handler_udp = handler.clone();
        join_set.spawn(async move {
            udp::run_udp_worker(udp_socket, handler_udp, i).await;
        });

        let tcp_listener = Arc::new(tcp::create_tcp_listener(domain, socket_addr)?);
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

    info!(
        "DNS server ready — {} workers on {}",
        num_workers, socket_addr
    );

    while join_set.join_next().await.is_some() {}
    Ok(())
}
