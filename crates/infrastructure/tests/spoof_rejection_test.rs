//! End-to-end anti-spoofing: drive `PoolManager::query` against a local UDP
//! responder and assert that off-path forgeries (wrong transaction ID, wrong DNS
//! Cookie) are rejected while a faithful echo is accepted.

use ferrous_dns_domain::{RecordType, UpstreamPool, UpstreamStrategy};
use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
use ferrous_dns_infrastructure::dns::forwarding::HardeningOpts;
use ferrous_dns_infrastructure::dns::load_balancer::PoolManager;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::Name;
use hickory_proto::serialize::binary::BinEncodable;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Clone, Copy)]
enum Mode {
    /// Echo the question with the correct transaction ID and no cookie.
    Faithful,
    /// Reply with a deliberately wrong transaction ID.
    WrongTxid,
    /// Echo the correct ID/question but attach a bogus cookie the client never sent.
    WrongCookie,
    /// Echo the correct ID but flip the case of one QNAME byte — an off-path forger
    /// guessing the 0x20-randomized case wrong.
    FlipQnameCase,
}

/// Spawns a UDP DNS responder on an ephemeral port and returns its address.
async fn spawn_responder(mode: Mode) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };

            let id = match mode {
                Mode::WrongTxid => req.id() ^ 0xFFFF,
                _ => req.id(),
            };
            let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
            resp.set_recursion_desired(true);
            resp.set_recursion_available(true);
            resp.set_response_code(ResponseCode::NoError);
            for q in req.queries() {
                if let Mode::FlipQnameCase = mode {
                    // Flip the 0x20 bit of the first label's first byte: since that
                    // byte is always an ASCII letter, this is a guaranteed (non-flaky)
                    // case mismatch versus the randomized QNAME the client sent.
                    let mut labels: Vec<Vec<u8>> = q.name().iter().map(|l| l.to_vec()).collect();
                    if let Some(b) = labels.first_mut().and_then(|l| l.first_mut()) {
                        *b ^= 0x20;
                    }
                    let mut flipped = Query::new();
                    flipped.set_name(Name::from_labels(labels).unwrap());
                    flipped.set_query_type(q.query_type());
                    flipped.set_query_class(q.query_class());
                    resp.add_query(flipped);
                } else {
                    resp.add_query(q.clone());
                }
            }
            if let Mode::WrongCookie = mode {
                let mut edns = Edns::new();
                edns.set_max_payload(4096);
                edns.set_version(0);
                edns.options_mut()
                    .insert(EdnsOption::Unknown(10, vec![9; 8]));
                resp.set_edns(edns);
            }

            let _ = socket.send_to(&resp.to_bytes().unwrap(), peer).await;
        }
    });

    addr
}

async fn manager(addr: SocketAddr) -> Arc<PoolManager> {
    let pool = UpstreamPool {
        name: "test".into(),
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

/// Like [`manager`], but with 0x20 QNAME case randomization enabled so the
/// validator enforces case-sensitive QNAME matching on Do53 responses.
async fn manager_hardened(addr: SocketAddr) -> Arc<PoolManager> {
    let pool = UpstreamPool {
        name: "test".into(),
        strategy: UpstreamStrategy::Parallel,
        priority: 1,
        servers: vec![format!("udp://{addr}")],
        weight: None,
    };
    Arc::new(
        PoolManager::new(vec![pool], None, QueryEventEmitter::new_disabled())
            .await
            .unwrap()
            .with_hardening(HardeningOpts {
                cookie: true,
                qname_0x20: true,
            }),
    )
}

async fn resolve(mode: Mode) -> Result<SocketAddr, ferrous_dns_domain::DomainError> {
    let addr = spawn_responder(mode).await;
    let pm = manager(addr).await;
    let domain: Arc<str> = Arc::from("example.com");
    pm.query(&domain, &RecordType::A, 2000, false)
        .await
        .map(|r| r.server)
}

#[tokio::test]
async fn faithful_upstream_response_is_accepted() {
    let result = resolve(Mode::Faithful).await;
    assert!(
        result.is_ok(),
        "faithful response must be accepted: {result:?}"
    );
}

#[tokio::test]
async fn spoofed_transaction_id_is_rejected() {
    let result = resolve(Mode::WrongTxid).await;
    assert!(
        result.is_err(),
        "a response with the wrong transaction ID must be rejected, got {result:?}"
    );
}

#[tokio::test]
async fn forged_cookie_is_rejected() {
    let result = resolve(Mode::WrongCookie).await;
    assert!(
        result.is_err(),
        "a response echoing a cookie the client never sent must be rejected, got {result:?}"
    );
}

#[tokio::test]
async fn case_forged_qname_is_rejected_with_0x20() {
    // With 0x20 on, a faithful upstream echoes the randomized QNAME case verbatim.
    // A response that gets the case wrong (an off-path forger) must be rejected.
    let addr = spawn_responder(Mode::FlipQnameCase).await;
    let pm = manager_hardened(addr).await;
    let domain: Arc<str> = Arc::from("example.com");
    let result = pm.query(&domain, &RecordType::A, 2000, false).await;
    assert!(
        result.is_err(),
        "a case-flipped QNAME echo must be rejected under 0x20, got {result:?}"
    );
}

/// Spawns a UDP responder that always answers with TC=1 (truncated), paired with
/// a TCP responder on the same port. The UDP TC=1 forces the truncation retry;
/// the TCP side replies per `tcp_mode`, letting us assert the validator also runs
/// on the post-truncation TCP path (`query_server`'s second validate site).
async fn spawn_truncating_pair(tcp_mode: Mode) -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = udp.local_addr().unwrap();
    let listener = TcpListener::bind(addr).await.unwrap();

    // UDP side: faithful echo but TC=1, so the response passes the first validate
    // and then triggers the TCP retry.
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((len, peer)) = udp.recv_from(&mut buf).await {
            let Ok(req) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let mut resp = Message::new(req.id(), MessageType::Response, OpCode::Query);
            resp.set_recursion_desired(true);
            resp.set_recursion_available(true);
            resp.set_response_code(ResponseCode::NoError);
            resp.set_truncated(true);
            for q in req.queries() {
                resp.add_query(q.clone());
            }
            let _ = udp.send_to(&resp.to_bytes().unwrap(), peer).await;
        }
    });

    // TCP side: length-prefixed DNS; the truncation retry lands here.
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut lenbuf = [0u8; 2];
                if stream.read_exact(&mut lenbuf).await.is_err() {
                    return;
                }
                let qlen = u16::from_be_bytes(lenbuf) as usize;
                let mut qbuf = vec![0u8; qlen];
                if stream.read_exact(&mut qbuf).await.is_err() {
                    return;
                }
                let Ok(req) = Message::from_vec(&qbuf) else {
                    return;
                };
                let id = match tcp_mode {
                    Mode::WrongTxid => req.id() ^ 0xFFFF,
                    _ => req.id(),
                };
                let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
                resp.set_recursion_desired(true);
                resp.set_recursion_available(true);
                resp.set_response_code(ResponseCode::NoError);
                for q in req.queries() {
                    resp.add_query(q.clone());
                }
                let bytes = resp.to_bytes().unwrap();
                let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
                framed.extend_from_slice(&bytes);
                let _ = stream.write_all(&framed).await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn validator_runs_on_post_truncation_tcp_retry() {
    let domain: Arc<str> = Arc::from("example.com");

    // Faithful TCP reply after a TC=1 UDP answer must resolve.
    let addr = spawn_truncating_pair(Mode::Faithful).await;
    let pm = manager(addr).await;
    let ok = pm.query(&domain, &RecordType::A, 2000, false).await;
    assert!(
        ok.is_ok(),
        "a faithful post-truncation TCP retry must resolve: {ok:?}"
    );

    // A forged TCP retry (wrong transaction ID) must be rejected at the second
    // validate site — not silently accepted because validation only ran on UDP.
    let addr = spawn_truncating_pair(Mode::WrongTxid).await;
    let pm = manager(addr).await;
    let bad = pm.query(&domain, &RecordType::A, 2000, false).await;
    assert!(
        bad.is_err(),
        "a wrong-txid TCP retry must be rejected, got {bad:?}"
    );
}
