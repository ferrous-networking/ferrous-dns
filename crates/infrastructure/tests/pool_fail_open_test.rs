//! When the health checker marks every upstream unhealthy, `PoolManager` must
//! still try them: the checker can lag reality, and refusing every query turns
//! a stale health verdict into a total outage.

use ferrous_dns_domain::{DnsProtocol, RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::load_balancer::{HealthChecker, PoolManager, ServerStatus};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

/// Answers every query faithfully except the health probe (`google.com`), which
/// gets SERVFAIL, so the server is reachable yet marked unhealthy.
async fn spawn_probe_failing_responder() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let is_probe = req
                .queries
                .iter()
                .any(|q| q.name().to_ascii().eq_ignore_ascii_case("google.com."));
            let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
            resp.metadata.recursion_desired = true;
            resp.metadata.recursion_available = true;
            resp.metadata.response_code = if is_probe {
                ResponseCode::ServFail
            } else {
                ResponseCode::NoError
            };
            for q in &req.queries {
                resp.add_query(q.clone());
            }
            let _ = socket.send_to(&resp.to_bytes().unwrap(), peer).await;
        }
    });
    addr
}

#[tokio::test]
async fn all_unhealthy_but_reachable_servers_still_resolve() {
    let addr = spawn_probe_failing_responder().await;
    let server = format!("udp://{addr}");
    let protocol: Arc<DnsProtocol> = Arc::new(server.parse().unwrap());

    let checker = Arc::new(HealthChecker::new(1, 1));
    let probed = Arc::clone(&protocol);
    let run_checker = Arc::clone(&checker);
    tokio::spawn(async move {
        run_checker
            .run(move || vec![Arc::clone(&probed)], 60, 500)
            .await;
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    while checker.get_status(&protocol) != ServerStatus::Unhealthy {
        assert!(
            tokio::time::Instant::now() < deadline,
            "health checker never marked the server unhealthy"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let pool = UpstreamPool {
        name: "only".into(),
        strategy: UpstreamStrategy::Failover,
        priority: 1,
        servers: vec![server],
        weight: None,
        ..Default::default()
    };
    let pm = PoolManager::new(vec![pool], Some(checker)).await.unwrap();
    let domain: Arc<str> = Arc::from("example.com");
    let result = pm.query(&domain, &RecordType::A, 2000, false).await;
    assert!(
        result.is_ok(),
        "a reachable server marked unhealthy must still be tried: {result:?}"
    );
}
