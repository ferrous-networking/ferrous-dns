//! `bind_web_listener`, which the web and DoH listeners bind through.

mod common;

use ferrous_dns::server::bind_web_listener;
use socket2::SockRef;
use std::net::SocketAddr;

#[tokio::test]
async fn test_a_v6_web_listener_is_dual_stack() {
    if common::skip_without_dual_stack("test_a_v6_web_listener_is_dual_stack") {
        return;
    }
    let listener = bind_web_listener("[::]:0".parse().unwrap()).unwrap();

    // Off explicitly, so `net.ipv6.bindv6only = 1` cannot take IPv4 away.
    assert!(!SockRef::from(&listener).only_v6().unwrap());
    let port = listener.local_addr().unwrap().port();
    let v4 = tokio::net::TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port)));
    let (connected, accepted) = tokio::join!(v4, listener.accept());
    connected.unwrap();
    assert_eq!(
        accepted.unwrap().1.ip().to_canonical().to_string(),
        "127.0.0.1"
    );
}

#[tokio::test]
async fn test_a_v4_web_listener_stays_af_inet() {
    let listener = bind_web_listener("127.0.0.1:0".parse().unwrap()).unwrap();

    // An AF_INET6 socket would report `::ffff:127.0.0.1` and need IPv6 in the kernel.
    assert!(listener.local_addr().unwrap().is_ipv4());
}
