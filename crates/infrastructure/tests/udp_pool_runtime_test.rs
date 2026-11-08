//! The upstream UDP socket pool is process-wide, but a tokio socket only works on
//! the runtime that registered it. Every `#[tokio::test]` runs its own runtime, so
//! a socket parked by a finished test must never reach the next one: when the
//! next test's fake upstream lands on the same ephemeral port, every query to it
//! failed with "A Tokio 1.x context was found, but it is being shutdown".

use bytes::Bytes;
use ferrous_dns_domain::{DomainError, UpstreamAddr};
use ferrous_dns_infrastructure::dns::transport::udp::UdpTransport;
use ferrous_dns_infrastructure::dns::transport::udp_pool::UdpSocketPool;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

const QUERY: [u8; 12] = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];

/// Echoes every datagram from a plain thread, so the server outlives the runtimes.
fn spawn_echo_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let addr = socket.local_addr().unwrap();
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((len, peer)) = socket.recv_from(&mut buf) {
            let _ = socket.send_to(&buf[..len], peer);
        }
    });
    addr
}

fn send_on_a_new_runtime(transport: &UdpTransport) -> Result<Bytes, DomainError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(transport.send(&QUERY, Duration::from_secs(2)))
}

#[test]
fn a_socket_parked_by_a_finished_runtime_is_not_handed_to_the_next() {
    let server = spawn_echo_server();
    let transport = UdpTransport::with_pool(
        UpstreamAddr::Resolved(server),
        Arc::new(UdpSocketPool::new(4, 64)),
    );

    send_on_a_new_runtime(&transport).expect("the first runtime's query");
    let answer = send_on_a_new_runtime(&transport)
        .expect("a later runtime must get a socket of its own, not the parked one");
    assert_eq!(answer.as_ref(), &QUERY);
}
