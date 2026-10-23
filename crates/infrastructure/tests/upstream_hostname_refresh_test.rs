//! An upstream given by hostname is looked up again when its answer's TTL
//! runs out, so a provider that moves to new IPs is followed without a
//! restart. A lookup that fails keeps the addresses the server already has:
//! losing them would take a working upstream down over one lost answer.

#[path = "support/refresh.rs"]
mod refresh;

use ferrous_dns_domain::UpstreamPool;
use ferrous_dns_infrastructure::dns::forwarding::HardeningOpts;
use ferrous_dns_infrastructure::dns::load_balancer::{
    run_hostname_refresh, HostnameRefreshTimes, Resolution,
};
use ferrous_dns_infrastructure::dns::transport::resolver::UpstreamHostResolver;
use ferrous_dns_infrastructure::dns::PoolManager;
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType as WireType};
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

const OLD_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const NEW_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
/// `.invalid` never resolves through the system resolver, the fallback when
/// the router has no answer, so only the router decides these lookups.
const GOOD: &str = "good.invalid";
const BAD: &str = "bad.invalid";
const OTHER: &str = "other.invalid";

/// Seconds-scale times, so the refresh task can be watched in a test.
const TIMES: HostnameRefreshTimes = HostnameRefreshTimes {
    min_ttl: Duration::ZERO,
    max_ttl: Duration::from_secs(3600),
    without_ttl: Duration::from_secs(3600),
    retry: Duration::from_millis(100),
    max_retry: Duration::from_secs(1),
};

/// A LAN router whose A answers can be changed mid-test: a name maps to its
/// addresses, handed out one per query in turn, and their TTL; a name it
/// does not know gets NXDOMAIN. AAAA queries get an empty answer.
#[derive(Clone, Default)]
struct Router {
    answers: Arc<Mutex<HashMap<String, (VecDeque<Ipv4Addr>, u32)>>>,
}

impl Router {
    fn set(&self, name: &str, ip: Ipv4Addr, ttl: u32) {
        self.rotate(name, &[ip], ttl);
    }

    /// Answers each A query for `name` with the next of `ips`.
    fn rotate(&self, name: &str, ips: &[Ipv4Addr], ttl: u32) {
        self.answers
            .lock()
            .unwrap()
            .insert(format!("{name}."), (ips.iter().copied().collect(), ttl));
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
                let answer = answers.lock().unwrap().get_mut(&name).map(|(ips, ttl)| {
                    let ip = ips[0];
                    if q.query_type() == WireType::A {
                        ips.rotate_left(1);
                    }
                    (ip, *ttl)
                });
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
    named_pool("only", servers)
}

fn named_pool(name: &str, servers: &[&str]) -> UpstreamPool {
    UpstreamPool {
        name: name.into(),
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

fn udp(name: &str) -> String {
    format!("udp://{name}:53")
}

#[tokio::test]
async fn a_new_address_is_picked_up_when_the_hostname_is_looked_up_again() {
    let router = Router::default();
    router.set(GOOD, OLD_IP, 60);
    let pm = manager(&router, &[&udp(GOOD)]).await;
    assert_eq!(addresses(&pm), vec![SocketAddr::from((OLD_IP, 53))]);

    router.set(GOOD, NEW_IP, 45);
    let resolution = pm.refresh_hostname(&udp(GOOD)).await;

    assert_eq!(resolution, Some(Resolution::Resolved { ttl: Some(45) }));
    assert_eq!(addresses(&pm), vec![SocketAddr::from((NEW_IP, 53))]);
}

#[tokio::test]
async fn a_failed_lookup_keeps_the_addresses_a_server_has() {
    let router = Router::default();
    router.set(GOOD, OLD_IP, 60);
    let pm = manager(&router, &[&udp(GOOD), &udp(BAD)]).await;
    assert!(pm.has_unresolved(), "{BAD} must start unresolved");
    assert_eq!(addresses(&pm), vec![SocketAddr::from((OLD_IP, 53))]);

    router.forget(GOOD);
    let resolution = pm.refresh_hostname(&udp(GOOD)).await;

    assert_eq!(resolution, Some(Resolution::Failed));
    assert_eq!(
        addresses(&pm),
        vec![SocketAddr::from((OLD_IP, 53))],
        "a lookup that fails must not take {GOOD}'s address away"
    );
}

/// Guard: a server no pool lists any more has nothing to refresh.
#[tokio::test]
async fn a_server_a_reload_removed_is_not_refreshed() {
    let router = Router::default();
    router.set(GOOD, OLD_IP, 60);
    router.set(OTHER, OLD_IP, 60);
    let pm = manager(&router, &[&udp(GOOD)]).await;
    pm.reload(vec![pool(&[&udp(OTHER)])]).await.unwrap();

    assert_eq!(pm.refresh_hostname(&udp(GOOD)).await, None);
}

#[test]
fn a_lookup_falls_due_at_its_ttl_held_to_the_bounds_or_on_a_doubling_backoff() {
    let times = HostnameRefreshTimes {
        min_ttl: Duration::from_secs(60),
        max_ttl: Duration::from_secs(3600),
        without_ttl: Duration::from_secs(300),
        retry: Duration::from_secs(30),
        max_retry: Duration::from_secs(300),
    };
    let secs = |resolution, failures| {
        times
            .next_lookup_in(resolution, failures)
            .map(|wait| wait.as_secs())
    };
    let resolved = |ttl| Resolution::Resolved { ttl };

    assert_eq!(secs(Resolution::Literal, 0), None);
    assert_eq!(secs(resolved(Some(600)), 0), Some(600));
    assert_eq!(secs(resolved(Some(5)), 0), Some(60), "held to the floor");
    assert_eq!(
        secs(resolved(Some(86_400)), 0),
        Some(3600),
        "held to the cap"
    );
    assert_eq!(
        secs(resolved(None), 0),
        Some(300),
        "the system resolver's answer"
    );
    assert_eq!(secs(Resolution::Failed, 1), Some(30));
    assert_eq!(secs(Resolution::Failed, 2), Some(60));
    assert_eq!(secs(Resolution::Failed, 3), Some(120));
    assert_eq!(secs(Resolution::Failed, 5), Some(300), "capped");
    assert_eq!(secs(Resolution::Failed, 40), Some(300), "no overflow");
}

#[tokio::test]
async fn the_refresh_task_follows_a_move_when_the_ttl_runs_out() {
    let router = Router::default();
    router.set(GOOD, OLD_IP, 1);
    let pm = Arc::new(manager(&router, &[&udp(GOOD)]).await);
    tokio::spawn(run_hostname_refresh(Arc::downgrade(&pm), TIMES));

    router.set(GOOD, NEW_IP, 1);

    let moved = refresh::wait_until(Duration::from_secs(5), || {
        addresses(&pm) == vec![SocketAddr::from((NEW_IP, 53))]
    })
    .await;
    assert!(moved, "still at {:?}", addresses(&pm));
}

#[tokio::test]
async fn the_refresh_task_retries_a_failed_lookup_until_it_resolves() {
    let router = Router::default();
    let pm = Arc::new(manager(&router, &[&udp(BAD)]).await);
    assert!(pm.has_unresolved());
    tokio::spawn(run_hostname_refresh(Arc::downgrade(&pm), TIMES));

    router.set(BAD, NEW_IP, 3600);

    let resolved = refresh::wait_until(Duration::from_secs(5), || !pm.has_unresolved()).await;
    assert!(resolved, "{BAD} never resolved");
    assert_eq!(addresses(&pm), vec![SocketAddr::from((NEW_IP, 53))]);
}

/// The task is asleep until the first server's lookup, an hour away; a
/// reload that brings a server with a 1 s TTL must wake it.
#[tokio::test]
async fn a_reload_arms_the_servers_it_brings() {
    let router = Router::default();
    router.set(GOOD, OLD_IP, 3600);
    router.set(OTHER, OLD_IP, 1);
    let pm = Arc::new(manager(&router, &[&udp(GOOD)]).await);
    tokio::spawn(run_hostname_refresh(Arc::downgrade(&pm), TIMES));
    tokio::time::sleep(Duration::from_millis(100)).await;

    pm.reload(vec![pool(&[&udp(OTHER)])]).await.unwrap();
    router.set(OTHER, NEW_IP, 1);

    let moved = refresh::wait_until(Duration::from_secs(5), || {
        addresses(&pm) == vec![SocketAddr::from((NEW_IP, 53))]
    })
    .await;
    assert!(moved, "still at {:?}", addresses(&pm));
}

/// A reload looks every server up again: its answer's TTL replaces the one
/// the server was scheduled by, here an hour.
#[tokio::test]
async fn a_reload_reschedules_a_server_by_the_ttl_it_just_got() {
    let router = Router::default();
    router.set(GOOD, OLD_IP, 3600);
    let pm = Arc::new(manager(&router, &[&udp(GOOD)]).await);
    tokio::spawn(run_hostname_refresh(Arc::downgrade(&pm), TIMES));
    tokio::time::sleep(Duration::from_millis(100)).await;

    router.set(GOOD, OLD_IP, 1);
    pm.reload(vec![pool(&[&udp(GOOD)])]).await.unwrap();
    router.set(GOOD, NEW_IP, 1);

    let moved = refresh::wait_until(Duration::from_secs(5), || {
        addresses(&pm) == vec![SocketAddr::from((NEW_IP, 53))]
    })
    .await;
    assert!(moved, "still at {:?}", addresses(&pm));
}

/// Two pools that list the same server look it up separately, so they may
/// hold different addresses; a refresh must bring every copy in line.
#[tokio::test]
async fn a_refresh_corrects_every_pool_that_lists_the_server() {
    let router = Router::default();
    router.rotate(GOOD, &[OLD_IP, NEW_IP], 60);
    let host_resolver =
        UpstreamHostResolver::new(Some(router.spawn().await), HardeningOpts::default());
    let pools = vec![
        named_pool("first", &[&udp(GOOD)]),
        named_pool("second", &[&udp(GOOD)]),
    ];
    let pm = PoolManager::with_host_resolver(pools, None, host_resolver)
        .await
        .unwrap();
    assert_eq!(
        addresses(&pm),
        vec![
            SocketAddr::from((OLD_IP, 53)),
            SocketAddr::from((NEW_IP, 53))
        ],
        "each pool got its own answer"
    );

    // The router's next answer is the first pool's.
    pm.refresh_hostname(&udp(GOOD)).await;

    assert_eq!(
        addresses(&pm),
        vec![
            SocketAddr::from((OLD_IP, 53)),
            SocketAddr::from((OLD_IP, 53))
        ]
    );
}

/// The task holds only a weak reference, so it must notice the manager is
/// gone even with no server to look up.
#[tokio::test]
async fn the_refresh_task_ends_with_its_pool_manager() {
    let router = Router::default();
    let pm = Arc::new(manager(&router, &["udp://192.0.2.53:53"]).await);
    let times = HostnameRefreshTimes {
        max_ttl: Duration::from_millis(100),
        ..TIMES
    };
    let task = tokio::spawn(run_hostname_refresh(Arc::downgrade(&pm), times));
    tokio::time::sleep(Duration::from_millis(50)).await;

    drop(pm);

    let ended = refresh::wait_until(Duration::from_secs(2), || task.is_finished()).await;
    assert!(ended, "the task outlived its pool manager");
}
