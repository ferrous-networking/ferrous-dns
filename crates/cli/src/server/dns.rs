use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use hickory_server::ServerFuture;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::{TcpListener, UdpSocket};
use tracing::info;

pub async fn start_dns_server(bind_addr: String, handler: DnsServerHandler) -> anyhow::Result<()> {
    let socket_addr: SocketAddr = bind_addr.parse()?;

    info!(bind_address = %socket_addr, "Starting DNS server");

    let domain = if socket_addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
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
    std_socket.set_nonblocking(true)?;
    let udp_socket = UdpSocket::from_std(std_socket)?;

    let tcp_listener = TcpListener::bind(socket_addr).await?;

    let mut server = ServerFuture::new(handler);
    server.register_socket(udp_socket);
    server.register_listener(tcp_listener, std::time::Duration::from_secs(10));

    info!("DNS server ready with optimized buffers");
    server.block_until_done().await?;
    Ok(())
}
