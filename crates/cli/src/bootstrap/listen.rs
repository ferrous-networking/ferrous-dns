use ferrous_dns_domain::config::ServerConfig;
use socket2::{Domain, Socket, Type};
use tracing::info;

/// The server config the listeners bind from: `server` itself, except that
/// `bind_address = "auto"` listens on IPv4 only when the kernel has no IPv6.
/// The stored config, saves and backups keep saying `"auto"`.
pub fn resolve_listen_config(server: &ServerConfig) -> ServerConfig {
    let mut listen = server.clone();
    let without_ipv6 = server.bind_address.without_ipv6();
    if without_ipv6 != server.bind_address && !kernel_has_ipv6() {
        listen.bind_address = without_ipv6;
        info!(
            "IPv6 is not available in this kernel: bind_address \"auto\" listens on IPv4 only (0.0.0.0)"
        );
    }
    listen
}

/// Only `EAFNOSUPPORT` means there is no IPv6; any other failure is left for
/// the bind to report.
fn kernel_has_ipv6() -> bool {
    match Socket::new(Domain::IPV6, Type::DGRAM, None) {
        Ok(_) => true,
        Err(e) => e.raw_os_error() != Some(libc::EAFNOSUPPORT),
    }
}
