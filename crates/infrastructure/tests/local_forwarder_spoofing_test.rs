//! `local_dns_server` answers are relayed to clients as raw wire bytes, so the
//! forwarder that fetches them must reject the same off-path forgeries the
//! upstream pools reject (see `spoof_rejection_test.rs`).

use ferrous_dns_domain::RecordType;
use ferrous_dns_infrastructure::dns::forwarding::DnsForwarder;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use tokio::net::UdpSocket;

const GENUINE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const FORGED: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 66);

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
            };
            for reply in replies {
                let _ = socket.send_to(&reply.to_bytes().unwrap(), peer).await;
            }
        }
    });

    addr
}

async fn resolve(mode: Responder) -> Result<Vec<IpAddr>, ferrous_dns_domain::DomainError> {
    let addr = spawn_responder(mode).await;
    DnsForwarder::new()
        .query(&addr.to_string(), "nas.lan", &RecordType::A, 2000)
        .await
        .map(|response| response.addresses)
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
