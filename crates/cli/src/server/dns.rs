use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use hickory_server::ServerFuture;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;

pub async fn start_dns_server(bind_addr: String, handler: DnsServerHandler) -> anyhow::Result<()> {
    let socket_addr: SocketAddr = bind_addr.parse()?;

    info!(bind_address = %socket_addr, "Starting DNS server");

    // Create socket2 with buffer tuning
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;

    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;

    // CRITICAL: Increase UDP buffers Default: ~256KB, Optimal for DNS: 4-8MB
    socket.set_recv_buffer_size(8 * 1024 * 1024)?; // 8MB recv
    socket.set_send_buffer_size(4 * 1024 * 1024)?; // 4MB send

    socket.bind(&socket_addr.into())?;
    socket.set_nonblocking(true)?;

    // Convert to tokio UdpSocket
    let std_socket: std::net::UdpSocket = socket.into();
    std_socket.set_nonblocking(true)?;
    let udp_socket = UdpSocket::from_std(std_socket)?;

    // TCP listener (unchanged)
    let tcp_listener = TcpListener::bind(socket_addr).await?;

    // Register with Hickory
    let mut server = ServerFuture::new(handler);
    server.register_socket(udp_socket);
    server.register_listener(tcp_listener, std::time::Duration::from_secs(10));

    info!("DNS server ready with optimized buffers");
    server.block_until_done().await?;
    Ok(())
}
