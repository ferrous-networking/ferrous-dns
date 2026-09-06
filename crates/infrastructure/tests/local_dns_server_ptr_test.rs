//! Regression: answers from `local_dns_server` must be relayed on the wire.
//!
//! `CoreResolver::resolve_local_tld` forwards private-range PTR queries (and
//! anything under `local_domain`) to the configured local DNS server, typically
//! the LAN router. The parser only lifts A/AAAA rdata into `addresses`, so a PTR
//! (or SRV/TXT/MX) answer has nothing to carry it unless the raw upstream bytes
//! are attached as `upstream_wire_data`, the way the pool path already does.
//! Before the fix the client received an empty NXDOMAIN for every LAN reverse
//! lookup even though the router had answered correctly.

use ferrous_dns_application::ports::DnsResolver;
use ferrous_dns_domain::{DnsQuery, RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
use ferrous_dns_infrastructure::dns::load_balancer::PoolManager;
use ferrous_dns_infrastructure::dns::resolver::CoreResolver;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, PTR};
use hickory_proto::rr::{Name, RData, Record, RecordType as WireRecordType};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::net::UdpSocket;

const LAN_HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 5);
const LAN_HOST_NAME: &str = "desktop.lan.";

/// Minimal "router" resolver: answers PTR with a fixed hostname and A with a
/// fixed address, echoing the query id and question like a real server.
async fn spawn_local_dns_server() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let Some(q) = req.queries.first().cloned() else {
                continue;
            };

            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = true;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = ResponseCode::NoError;
            resp.add_query(q.clone());

            match q.query_type() {
                WireRecordType::PTR => {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::PTR(PTR(Name::from_str(LAN_HOST_NAME).unwrap())),
                    ));
                }
                WireRecordType::A => {
                    resp.add_answer(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A(LAN_HOST_IP)),
                    ));
                }
                _ => {}
            }

            let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
        }
    });

    addr
}

/// A pool manager is required by `CoreResolver::new`; point it at the same
/// responder. It must not be consulted for the queries under test.
async fn manager(addr: SocketAddr) -> Arc<PoolManager> {
    let pool = UpstreamPool {
        name: "unused".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![format!("udp://{addr}")],
        weight: None,
    };
    Arc::new(
        PoolManager::new(vec![pool], None, QueryEventEmitter::new_disabled())
            .await
            .unwrap(),
    )
}

async fn resolver_with_local_server(addr: SocketAddr) -> CoreResolver {
    CoreResolver::new(manager(addr).await, 2000, false)
        .with_local_domain(Some("lan".to_string()))
        .with_local_dns_server(Some(addr.to_string()))
}

#[tokio::test]
async fn test_local_dns_server_ptr_relayed_on_wire() {
    let addr = spawn_local_dns_server().await;
    let resolver = resolver_with_local_server(addr).await;

    let query = DnsQuery::new("5.0.0.10.in-addr.arpa", RecordType::PTR);
    let resolution = resolver
        .resolve(&query)
        .await
        .expect("PTR via local_dns_server must resolve");

    assert!(resolution.local_dns, "answer must be marked as local DNS");
    assert_eq!(
        resolution.upstream_server.as_deref(),
        Some(addr.to_string().as_str())
    );

    let wire = resolution
        .upstream_wire_data
        .as_ref()
        .expect("PTR answer must carry the upstream wire bytes (regression: was None)");
    let msg = Message::from_vec(wire).expect("wire bytes must be a valid DNS message");

    let ptr_targets: Vec<String> = msg
        .answers
        .iter()
        .filter_map(|r| match &r.data {
            RData::PTR(p) => Some(p.0.to_utf8()),
            _ => None,
        })
        .collect();
    assert_eq!(
        ptr_targets,
        vec![LAN_HOST_NAME.to_string()],
        "relayed message must contain the router's PTR answer"
    );
    assert_eq!(resolution.min_ttl, Some(60));
}

#[tokio::test]
async fn test_local_dns_server_a_record_populates_addresses() {
    let addr = spawn_local_dns_server().await;
    let resolver = resolver_with_local_server(addr).await;

    let query = DnsQuery::new("nas.lan", RecordType::A);
    let resolution = resolver
        .resolve(&query)
        .await
        .expect("A under local_domain must resolve via local_dns_server");

    assert!(resolution.local_dns);
    assert_eq!(resolution.addresses.to_vec(), vec![IpAddr::V4(LAN_HOST_IP)]);
    assert!(
        resolution.upstream_wire_data.is_some(),
        "address answers should also carry wire bytes, matching the pool path"
    );
}
