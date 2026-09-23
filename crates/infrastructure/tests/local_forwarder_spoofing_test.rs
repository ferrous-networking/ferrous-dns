//! `local_dns_server` answers are relayed to clients as raw wire bytes, so the
//! forwarder that fetches them must reject the same off-path forgeries the
//! upstream pools reject (see `spoof_rejection_test.rs`).

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::forwarding::{DnsForwarder, HardeningOpts};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const GENUINE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const FORGED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 66);

const WITH_0X20: HardeningOpts = HardeningOpts {
    cookie: true,
    qname_0x20: true,
};

#[derive(Clone, Copy)]
enum Responder {
    /// Answers the question it was asked with [`GENUINE`].
    Faithful,
    /// Sends a forged answer with the wrong transaction ID first, then the
    /// genuine one — the race an off-path forger runs.
    WrongTxidFirst,
    /// Right transaction ID, but the answer is for another name.
    WrongQuestion,
    /// Right transaction ID and question, plus a DNS Cookie the client never sent.
    WrongCookie,
    /// Right transaction ID, but the query name comes back with one letter's
    /// case flipped — what a forger guessing the 0x20 case, or a router that
    /// normalizes names, sends.
    FlipQnameCase,
    /// Answers over UDP with TC=1 and no records; the TCP listener on the same
    /// port holds the genuine answer.
    Truncated,
}

fn reply(request: &Message, id: u16, question: Query, address: Ipv4Addr) -> Message {
    let mut reply = Message::new(id, MessageType::Response, OpCode::Query);
    reply.metadata.recursion_desired = request.metadata.recursion_desired;
    reply.metadata.recursion_available = true;
    reply.metadata.response_code = ResponseCode::NoError;
    let name = question.name().clone();
    reply.add_query(question);
    reply.add_answer(Record::from_rdata(name, 300, RData::A(A(address))));
    reply
}

/// Spawns a UDP responder standing in for the router behind `local_dns_server`.
async fn spawn_responder(mode: Responder) -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();

    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
            let Ok(request) = Message::from_vec(&buf[..len]) else {
                continue;
            };
            let Some(question) = request.queries.first().cloned() else {
                continue;
            };

            let replies = match mode {
                Responder::Faithful => vec![reply(&request, request.id, question, GENUINE)],
                Responder::WrongTxidFirst => vec![
                    reply(&request, request.id ^ 0xFFFF, question.clone(), FORGED),
                    reply(&request, request.id, question, GENUINE),
                ],
                Responder::WrongQuestion => {
                    let mut other = question.clone();
                    other.set_name(Name::from_str("forged.example.").unwrap());
                    vec![reply(&request, request.id, other, FORGED)]
                }
                Responder::WrongCookie => {
                    let mut forged = reply(&request, request.id, question, FORGED);
                    let mut edns = Edns::new();
                    edns.set_max_payload(1232);
                    edns.options_mut()
                        .insert(EdnsOption::Unknown(10, vec![9; 8]));
                    forged.set_edns(edns);
                    vec![forged]
                }
                Responder::FlipQnameCase => {
                    let mut labels: Vec<Vec<u8>> =
                        question.name().iter().map(|label| label.to_vec()).collect();
                    labels[0][0] ^= 0x20;
                    let mut flipped = question.clone();
                    flipped.set_name(Name::from_labels(labels).unwrap());
                    vec![reply(&request, request.id, flipped, GENUINE)]
                }
                Responder::Truncated => {
                    let mut truncated =
                        Message::new(request.id, MessageType::Response, OpCode::Query);
                    truncated.metadata.truncation = true;
                    truncated.add_query(question);
                    vec![truncated]
                }
            };
            for reply in replies {
                let _ = socket.send_to(&reply.to_bytes().unwrap(), peer).await;
            }
        }
    });

    if let Responder::Truncated = mode {
        spawn_tcp_responder(TcpListener::bind(addr).await.unwrap());
    }

    addr
}

/// Length-prefixed DNS over TCP, answering with [`GENUINE`].
fn spawn_tcp_responder(listener: TcpListener) {
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut len = [0u8; 2];
            if stream.read_exact(&mut len).await.is_err() {
                continue;
            }
            let mut query = vec![0u8; u16::from_be_bytes(len) as usize];
            if stream.read_exact(&mut query).await.is_err() {
                continue;
            }
            let Ok(request) = Message::from_vec(&query) else {
                continue;
            };
            let Some(question) = request.queries.first().cloned() else {
                continue;
            };
            let bytes = reply(&request, request.id, question, GENUINE)
                .to_bytes()
                .unwrap();
            let mut framed = (bytes.len() as u16).to_be_bytes().to_vec();
            framed.extend_from_slice(&bytes);
            let _ = stream.write_all(&framed).await;
        }
    });
}

async fn resolve_with(
    mode: Responder,
    forwarder: DnsForwarder,
) -> Result<Vec<IpAddr>, ferrous_dns_domain::DomainError> {
    let addr = spawn_responder(mode).await;
    forwarder
        .query(&addr.to_string(), "nas.lan", &RecordType::A, 2000)
        .await
        .map(|response| response.addresses)
}

async fn resolve(mode: Responder) -> Result<Vec<IpAddr>, ferrous_dns_domain::DomainError> {
    resolve_with(mode, DnsForwarder::new()).await
}

#[tokio::test]
async fn faithful_answer_is_accepted() {
    let result = resolve(Responder::Faithful).await;

    assert_eq!(result.unwrap(), vec![IpAddr::V4(GENUINE)]);
}

#[tokio::test]
async fn forged_answer_with_wrong_transaction_id_does_not_win_the_race() {
    let result = resolve(Responder::WrongTxidFirst).await;

    assert_eq!(
        result.unwrap(),
        vec![IpAddr::V4(GENUINE)],
        "the forged datagram arrived first and must have been skipped"
    );
}

#[tokio::test]
async fn answer_for_another_question_is_rejected() {
    let result = resolve(Responder::WrongQuestion).await;

    assert!(
        result.is_err(),
        "an answer for a name we did not ask must be rejected, got {result:?}"
    );
}

#[tokio::test]
async fn forged_cookie_is_rejected() {
    let result = resolve(Responder::WrongCookie).await;

    assert!(
        result.is_err(),
        "an answer echoing a cookie we never sent must be rejected, got {result:?}"
    );
}

#[tokio::test]
async fn case_flipped_answer_is_rejected_with_0x20() {
    let forwarder = DnsForwarder::new().with_hardening(WITH_0X20);

    let result = resolve_with(Responder::FlipQnameCase, forwarder).await;

    assert!(
        result.is_err(),
        "a case-flipped query name must be rejected under 0x20, got {result:?}"
    );
}

/// The randomized case must not leak to clients: the answer is relayed as raw
/// bytes, so the forwarder lowercases it once the echo has been checked.
#[tokio::test]
async fn answer_under_0x20_is_relayed_lowercased() {
    let addr = spawn_responder(Responder::Faithful).await;

    let response = DnsForwarder::new()
        .with_hardening(WITH_0X20)
        .query(&addr.to_string(), "nas.lan", &RecordType::A, 2000)
        .await
        .unwrap();

    let relayed = Message::from_vec(&response.raw_bytes).unwrap();
    assert_eq!(relayed.queries[0].name().to_ascii(), "nas.lan.");
    assert_eq!(response.addresses, vec![IpAddr::V4(GENUINE)]);
}

#[tokio::test]
async fn truncated_answer_is_retried_over_tcp() {
    let result = resolve(Responder::Truncated).await;

    assert_eq!(result.unwrap(), vec![IpAddr::V4(GENUINE)]);
}
