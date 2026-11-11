//! The socket family the DNS listeners bind (#386): an IPv4 address gets an
//! AF_INET socket, which needs no IPv6 in the kernel, and an IPv6 address a
//! dual-stack AF_INET6 one.

mod common;

use ferrous_dns::server::{
    bind_doq_endpoint, bind_tcp_listener, bind_web_listener, load_server_tls_config,
};
use socket2::SockRef;
use std::net::SocketAddr;

#[tokio::test]
async fn test_an_ipv4_tcp_listener_stays_af_inet() {
    let listener = bind_tcp_listener("127.0.0.1:0".parse().unwrap()).unwrap();

    // An AF_INET6 socket would report `::ffff:127.0.0.1` and need IPv6 in the kernel.
    assert!(listener.local_addr().unwrap().is_ipv4());
}

#[tokio::test]
async fn test_an_ipv6_tcp_listener_is_dual_stack() {
    if common::skip_without_dual_stack("test_an_ipv6_tcp_listener_is_dual_stack") {
        return;
    }
    let listener = bind_tcp_listener("[::]:0".parse().unwrap()).unwrap();

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
async fn test_an_ipv4_doq_endpoint_stays_af_inet() {
    ferrous_dns::install_crypto_provider();
    let dir = tempfile::tempdir().unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let (cert_path, key_path) = (dir.path().join("cert.pem"), dir.path().join("key.pem"));
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    let tls = load_server_tls_config(
        cert_path.to_str().unwrap(),
        key_path.to_str().unwrap(),
        "dns_listener_family_test",
        &[b"doq"],
    )
    .unwrap()
    .unwrap();

    let endpoint = bind_doq_endpoint("127.0.0.1:0".parse().unwrap(), tls).unwrap();

    assert!(endpoint.local_addr().unwrap().is_ipv4());
}

#[tokio::test]
async fn test_dns_listeners_share_their_port_and_the_web_does_not() {
    let dns = bind_tcp_listener("127.0.0.1:0".parse().unwrap()).unwrap();
    let web = bind_web_listener("127.0.0.1:0".parse().unwrap()).unwrap();

    // One DNS listener per worker shares the port; a second web server must
    // fail to bind instead.
    assert!(SockRef::from(&dns).reuse_port().unwrap());
    assert!(!SockRef::from(&web).reuse_port().unwrap());
}
