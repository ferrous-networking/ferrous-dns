use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

/// Opens the socket of a listener on `bind`, in the address's family: AF_INET
/// for IPv4, which needs no IPv6 in the kernel, and AF_INET6 for IPv6 with
/// `IPV6_V6ONLY` off, so `[::]` serves IPv4 too whatever
/// `net.ipv6.bindv6only` says. The caller sets its own options, then binds.
pub(crate) fn open_listener_socket(
    bind: SocketAddr,
    ty: Type,
    protocol: Protocol,
) -> anyhow::Result<Socket> {
    let socket = Socket::new(Domain::for_address(bind), ty, Some(protocol)).map_err(|e| {
        if bind.is_ipv6() && e.raw_os_error() == Some(libc::EAFNOSUPPORT) {
            anyhow::Error::from(e).context(format!(
                "{bind} is an IPv6 address and this kernel has no IPv6: listen on an IPv4 address instead"
            ))
        } else {
            e.into()
        }
    })?;
    if bind.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    Ok(socket)
}
