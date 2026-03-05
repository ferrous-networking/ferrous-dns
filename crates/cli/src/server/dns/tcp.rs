use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use tokio::net::TcpListener;

pub(super) fn create_tcp_listener(
    domain: Domain,
    socket_addr: SocketAddr,
) -> anyhow::Result<TcpListener> {
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if socket_addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    socket.bind(&socket_addr.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    let std_listener: std::net::TcpListener = socket.into();
    Ok(TcpListener::from_std(std_listener)?)
}
