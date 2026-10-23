//! An upstream given by hostname is looked up again when its answer's TTL
//! runs out, so a provider that moves to new IPs is followed without a
//! restart. A lookup that fails keeps the addresses the server already has:
//! losing them would take a working upstream down over one lost answer.

use ferrous_dns_domain::UpstreamPool;
use ferrous_dns_infrastructure::dns::forwarding::HardeningOpts;
use ferrous_dns_infrastructure::dns::transport::resolver::UpstreamHostResolver;
use ferrous_dns_infrastructure::dns::PoolManager;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType as WireType};
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

const OLD_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const NEW_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
/// `.invalid` never resolves through the system resolver, the fallback when
/// the router has no answer, so only the router decides these lookups.
const GOOD: &str = "good.invalid";
const BAD: &str = "bad.invalid";

/// A LAN router whose A answers can be changed mid-test: a name maps to its
/// address and TTL, and a name it does not know gets NXDOMAIN. AAAA queries
/// get an empty answer.
#[derive(Clone, Default)]
struct Router {
    answers: Arc<Mutex<HashMap<String, (Ipv4Addr, u32)>>>,
}

impl Router {
    fn set(&self, name: &str, ip: Ipv4Addr, ttl: u32) {
        self.answers
            .lock()
            .unwrap()
            .insert(format!("{name}."), (ip, ttl));
    }

    fn forget(&self, name: &str) {
        self.answers.lock().unwrap().remove(&format!("{name}."));
    }

    async fn spawn(&self) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let answers = Arc::clone(&self.answers);
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
                resp.metadata.recursion_desired = req.metadata.recursion_desired;
                resp.metadata.recursion_available = true;
                resp.add_query(q.clone());
                let name = q.name().to_ascii().to_ascii_lowercase();
                let answer = answers.lock().unwrap().get(&name).copied();
                match answer {
                    None => resp.metadata.response_code = ResponseCode::NXDomain,
                    Some((ip, ttl)) => {
                        resp.metadata.response_code = ResponseCode::NoError;
                        if q.query_type() == WireType::A {
                            resp.add_answer(Record::from_rdata(
                                q.name().clone(),
                                ttl,
                                RData::A(A(ip)),
                            ));
                        }
                    }
                }
                let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }
}

fn pool(servers: &[&str]) -> UpstreamPool {
    UpstreamPool {
        name: "only".into(),
        servers: servers.iter().map(|s| s.to_string()).collect(),
        ..Default::default()
    }
}

async fn manager(router: &Router, servers: &[&str]) -> PoolManager {
    let host_resolver =
        UpstreamHostResolver::new(Some(router.spawn().await), HardeningOpts::default());
    PoolManager::with_host_resolver(vec![pool(servers)], None, host_resolver)
        .await
        .unwrap()
}

fn addresses(pm: &PoolManager) -> Vec<SocketAddr> {
    let mut addrs = pm.get_all_servers();
    addrs.sort();
    addrs
}

#[tokio::test]
async fn a_new_address_is_picked_up_when_the_hostname_is_looked_up_again() {
    let router = Router::default();
    router.set(GOOD, OLD_IP, 60);
    let pm = manager(&router, &[&format!("udp://{GOOD}:53")]).await;
    assert_eq!(addresses(&pm), vec![SocketAddr::from((OLD_IP, 53))]);

    router.set(GOOD, NEW_IP, 60);
    pm.retry_unresolved().await;

    assert_eq!(addresses(&pm), vec![SocketAddr::from((NEW_IP, 53))]);
}

#[tokio::test]
async fn a_failed_lookup_keeps_the_addresses_a_server_has() {
    let router = Router::default();
    router.set(GOOD, OLD_IP, 60);
    let pm = manager(
        &router,
        &[&format!("udp://{GOOD}:53"), &format!("udp://{BAD}:53")],
    )
    .await;
    assert!(pm.has_unresolved(), "{BAD} must start unresolved");
    assert_eq!(addresses(&pm), vec![SocketAddr::from((OLD_IP, 53))]);

    router.forget(GOOD);
    pm.retry_unresolved().await;

    assert_eq!(
        addresses(&pm),
        vec![SocketAddr::from((OLD_IP, 53))],
        "a lookup that fails must not take {GOOD}'s address away"
    );
}
