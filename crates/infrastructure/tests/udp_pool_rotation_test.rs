//! Source-port rotation in the upstream UDP socket pool.
//!
//! A pooled socket used to keep its ephemeral port for the life of the process,
//! so the few ports an upstream ever saw were fixed and an attacker who learned
//! one could reuse it indefinitely — leaving off-path forgery to guess the
//! 16-bit transaction ID alone. Sockets now retire after a bounded number of
//! queries so a discovered port goes stale.

use ferrous_dns_infrastructure::dns::transport::udp_pool::UdpSocketPool;
use std::collections::HashSet;
use std::net::SocketAddr;

/// Upper bound of the rotation budget (1000 + 25% jitter). Driving past it
/// guarantees a retirement without depending on the drawn value.
const ABOVE_MAX_BUDGET: usize = 1300;

fn upstream() -> SocketAddr {
    // Never contacted — acquire only binds a local socket.
    "127.0.0.1:65000".parse().unwrap()
}

#[tokio::test]
async fn socket_is_reused_before_the_rotation_budget() {
    let pool = UdpSocketPool::new(4, 64);
    let server = upstream();

    let first = pool.acquire(server).await.unwrap();
    let port = first.socket().local_addr().unwrap().port();
    drop(first);

    let second = pool.acquire(server).await.unwrap();
    assert_eq!(
        second.socket().local_addr().unwrap().port(),
        port,
        "a socket well under its budget must come back from the pool"
    );
    drop(second);

    let stats = pool.stats();
    assert_eq!(stats.total_created, 1, "no second socket should be bound");
    assert_eq!(stats.total_retired, 0);
}

#[tokio::test]
async fn source_port_rotates_once_the_budget_is_spent() {
    let pool = UdpSocketPool::new(4, 64);
    let server = upstream();

    let mut ports = HashSet::new();
    for _ in 0..ABOVE_MAX_BUDGET {
        let socket = pool.acquire(server).await.unwrap();
        ports.insert(socket.socket().local_addr().unwrap().port());
    }

    let stats = pool.stats();
    assert!(
        stats.total_retired >= 1,
        "at least one socket must retire within {ABOVE_MAX_BUDGET} uses, got {stats:?}"
    );
    assert!(
        stats.total_created >= 2,
        "a retired socket must be replaced by a freshly bound one, got {stats:?}"
    );
    assert!(
        ports.len() >= 2,
        "rotation must actually change the source port, saw {} distinct",
        ports.len()
    );
}

#[tokio::test]
async fn a_poisoned_socket_is_dropped_without_counting_as_retired() {
    let pool = UdpSocketPool::new(4, 64);
    let server = upstream();

    let mut socket = pool.acquire(server).await.unwrap();
    socket.poison();
    drop(socket);

    let stats = pool.stats();
    assert_eq!(
        stats.total_pooled, 0,
        "a poisoned socket must not be pooled"
    );
    assert_eq!(
        stats.total_retired, 0,
        "poisoning is an error path, not budget-driven rotation"
    );
}
