//! Looking an upstream hostname up through `local_dns_server` asks for A and
//! AAAA together. A lost datagram must not leave the upstream with one family
//! only: once it has any address it is never looked up again, so an IPv6-only
//! answer makes it unreachable from an IPv4-only host for good.

use ferrous_dns_infrastructure::dns::forwarding::HardeningOpts;
use ferrous_dns_infrastructure::dns::transport::resolver::UpstreamHostResolver;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType as WireType};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

const V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

/// A router that answers `upstream.test` for both families but drops the
/// first A query it receives.
async fn spawn_router_dropping_first_a() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        let mut dropped = false;
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let Some(q) = req.queries.first().cloned() else {
                continue;
            };
            if q.query_type() == WireType::A && !dropped {
                dropped = true;
                continue;
            }
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = req.metadata.recursion_desired;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_query(q.clone());
            let rdata = match q.query_type() {
                WireType::A => RData::A(A(V4)),
                WireType::AAAA => RData::AAAA(AAAA(V6)),
                _ => continue,
            };
            resp.add_answer(Record::from_rdata(q.name().clone(), 300, rdata));
            let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });
    addr
}

#[tokio::test]
async fn a_lost_answer_for_one_family_is_asked_again() {
    let router = spawn_router_dropping_first_a().await;
    let resolver = UpstreamHostResolver::new(Some(router), HardeningOpts::default());

    let mut addrs = resolver
        .resolve_all("upstream.test", 853, Duration::from_secs(5))
        .await
        .unwrap();
    addrs.sort();

    assert_eq!(
        addrs,
        vec![SocketAddr::from((V4, 853)), SocketAddr::from((V6, 853))]
    );
}
