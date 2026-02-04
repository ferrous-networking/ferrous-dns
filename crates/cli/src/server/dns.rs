use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use hickory_server::ServerFuture;
use std::net::SocketAddr;
use std::str::FromStr;
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;

pub async fn start_dns_server(bind_addr: String, handler: DnsServerHandler) -> anyhow::Result<()> {
    let socket_addr = SocketAddr::from_str(&bind_addr)?;

    info!(bind_address = %socket_addr, "Starting DNS server");

    // Create UDP socket
    let udp_socket = UdpSocket::bind(socket_addr).await?;
    info!(protocol = "UDP", "DNS server listening");

    // Create TCP listener
    let tcp_listener = TcpListener::bind(socket_addr).await?;
    info!(protocol = "TCP", "DNS server listening");

    // Start server
    let mut server = ServerFuture::new(handler);
    server.register_socket(udp_socket);
    server.register_listener(tcp_listener, std::time::Duration::from_secs(10));

    info!("DNS server ready to accept queries");

    server.block_until_done().await?;

    Ok(())
}
