mod pktinfo;
mod tcp;
mod udp;

use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use socket2::Domain;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{error, info};

pub async fn start_dns_server(
    bind_addr: String,
    handler: DnsServerHandler,
    num_workers: usize,
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
        let udp_socket = Arc::new(udp::create_udp_socket(domain, socket_addr)?);
        let handler_udp = handler.clone();
        join_set.spawn(async move {
            udp::run_udp_worker(udp_socket, handler_udp, i).await;
        });

        let tcp_listener = tcp::create_tcp_listener(domain, socket_addr)?;
        let handler_tcp = (*handler).clone();
        join_set.spawn(async move {
            let mut server = hickory_server::ServerFuture::new(handler_tcp);
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
