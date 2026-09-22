//! Source-port rotation and bounded admission in the upstream UDP socket pool.
//!
//! A pooled socket used to keep its ephemeral port for the life of the process,
//! so the few ports an upstream ever saw were fixed and an attacker who learned
//! one could reuse it indefinitely — leaving off-path forgery to guess the
//! 16-bit transaction ID alone. Sockets now retire after a bounded number of
//! queries so a discovered port goes stale.

use ferrous_dns_domain::{DomainError, UpstreamAddr};
use ferrous_dns_infrastructure::dns::forwarding::ResponseParser;
use ferrous_dns_infrastructure::dns::transport::udp_pool::UdpSocketPool;
use ferrous_dns_infrastructure::dns::transport::{udp::UdpTransport, DnsTransport};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

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
    let pool = UdpSocketPool::new(4, 1);
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
    let pool = UdpSocketPool::new(4, 1);
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

    let replacement = timeout(Duration::from_secs(1), pool.acquire(server))
        .await
        .expect("poisoning must return checkout capacity")
        .unwrap();
    assert_eq!(pool.stats().total_created, 2);
    drop(replacement);
}

#[tokio::test]
async fn new_sockets_wait_for_checkout_capacity() {
    let pool = UdpSocketPool::new(4, 1);
    let first = pool.acquire(upstream()).await.unwrap();
    let other_server = SocketAddr::from(([127, 0, 0, 1], 65001));
    let mut waiting = Box::pin(pool.acquire(other_server));
    assert!(futures::poll!(&mut waiting).is_pending());
    assert_eq!(pool.stats().total_created, 1);

    drop(first);
    let second = timeout(Duration::from_secs(1), waiting)
        .await
        .expect("returning a socket must admit a new exchange")
        .unwrap();
    assert_eq!(second.server(), other_server);
    assert_eq!(pool.stats().total_created, 2);
}

#[tokio::test]
async fn reused_sockets_share_the_global_checkout_limit() {
    let pool = UdpSocketPool::new(4, 1);
    let first_server = upstream();
    let second_server = SocketAddr::from(([127, 0, 0, 1], 65001));
    drop(pool.acquire(first_server).await.unwrap());
    let second = pool.acquire(second_server).await.unwrap();
    let second_port = second.socket().local_addr().unwrap().port();
    drop(second);

    let first = pool.acquire(first_server).await.unwrap();
    let mut waiting = Box::pin(pool.acquire(second_server));
    assert!(futures::poll!(&mut waiting).is_pending());
    drop(first);

    let second = timeout(Duration::from_secs(1), waiting)
        .await
        .expect("returning a reused socket must restore capacity")
        .unwrap();
    assert_eq!(second.socket().local_addr().unwrap().port(), second_port);
    assert_eq!(pool.stats().total_created, 2);
}

#[tokio::test]
async fn cancelling_queued_and_admitted_waiters_preserves_capacity() {
    let pool = UdpSocketPool::new(4, 1);
    let first = pool.acquire(upstream()).await.unwrap();
    let first_port = first.socket().local_addr().unwrap().port();
    let mut cancelled = Box::pin(pool.acquire(upstream()));
    let mut admitted = Box::pin(pool.acquire(upstream()));
    let mut survivor = Box::pin(pool.acquire(upstream()));
    assert!(futures::poll!(&mut cancelled).is_pending());
    assert!(futures::poll!(&mut admitted).is_pending());
    assert!(futures::poll!(&mut survivor).is_pending());

    drop(cancelled);
    drop(first);
    // Capacity has been assigned, but the waiter has not resumed to take it.
    drop(admitted);
    let socket = timeout(Duration::from_secs(1), survivor)
        .await
        .expect("cancelled waiters must not consume checkout capacity")
        .unwrap();
    assert_eq!(socket.socket().local_addr().unwrap().port(), first_port);
}

#[tokio::test]
async fn saturated_transport_times_out_without_consuming_capacity() {
    let pool = Arc::new(UdpSocketPool::new(4, 1));
    let occupied = pool.acquire(upstream()).await.unwrap();
    let transport = UdpTransport::with_pool(UpstreamAddr::Resolved(upstream()), pool.clone());
    let result = timeout(
        Duration::from_secs(1),
        transport.send(&[0; 12], Duration::from_millis(10)),
    )
    .await
    .expect("admission must honor the transport timeout");
    let error = result.expect_err("a saturated pool must not complete the exchange");
    assert!(
        matches!(error, DomainError::TransportTimeout { .. }),
        "got {error:?}"
    );
    assert!(
        ResponseParser::is_transport_error(&error),
        "local saturation must let the pool manager fail over"
    );
    drop(occupied);
    let next = timeout(Duration::from_secs(1), pool.acquire(upstream()))
        .await
        .expect("timed-out admission must not consume capacity")
        .unwrap();
    assert_eq!(next.server(), upstream());
}
