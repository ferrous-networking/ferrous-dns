//! A scriptable UDP upstream for the conditional-forwarding tests: it answers
//! A queries with its own address, and records what it was asked.
#![allow(dead_code)]

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::UdpSocket;

/// How the upstream replies.
#[derive(Clone, Copy, Debug)]
pub enum Answer {
    /// An A record with this address for A queries; NODATA for other types.
    Address(Ipv4Addr),
    /// A CNAME to the target name, followed by the target's A record.
    Cname(&'static str, Ipv4Addr),
    NxDomain,
    /// No reply at all, as a server that is down.
    Silent,
}

pub struct Upstream {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    last_dnssec_ok: Arc<AtomicBool>,
    asked: Arc<Mutex<Vec<(String, RecordType)>>>,
    answer: Arc<Mutex<Answer>>,
    delay: Arc<Mutex<Duration>>,
}

impl Upstream {
    pub async fn spawn(answer: Answer) -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let upstream = Self {
            addr: socket.local_addr().unwrap(),
            queries: Arc::new(AtomicUsize::new(0)),
            last_dnssec_ok: Arc::new(AtomicBool::new(false)),
            asked: Arc::new(Mutex::new(Vec::new())),
            answer: Arc::new(Mutex::new(answer)),
            delay: Arc::new(Mutex::new(Duration::ZERO)),
        };
        let queries = Arc::clone(&upstream.queries);
        let last_dnssec_ok = Arc::clone(&upstream.last_dnssec_ok);
        let asked = Arc::clone(&upstream.asked);
        let current = Arc::clone(&upstream.answer);
        let delay = Arc::clone(&upstream.delay);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf).await {
                let Ok(req) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                queries.fetch_add(1, Ordering::SeqCst);
                last_dnssec_ok.store(
                    req.edns.as_ref().is_some_and(|e| e.flags().dnssec_ok),
                    Ordering::SeqCst,
                );
                for q in &req.queries {
                    asked
                        .lock()
                        .unwrap()
                        .push((q.name().to_ascii().to_ascii_lowercase(), q.query_type()));
                }
                let answer = *current.lock().unwrap();
                let wait = *delay.lock().unwrap();
                let Some(bytes) = reply(&req, answer) else {
                    continue;
                };
                let socket = Arc::clone(&socket);
                tokio::spawn(async move {
                    tokio::time::sleep(wait).await;
                    let _ = socket.send_to(&bytes, peer).await;
                });
            }
        });
        upstream
    }

    pub fn url(&self) -> String {
        format!("udp://{}", self.addr)
    }

    pub fn queries(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }

    /// Whether the last query set the EDNS DO bit.
    pub fn last_dnssec_ok(&self) -> bool {
        self.last_dnssec_ok.load(Ordering::SeqCst)
    }

    /// Every (lowercased, absolute) name and type asked so far.
    pub fn asked(&self) -> Vec<(String, RecordType)> {
        self.asked.lock().unwrap().clone()
    }

    pub fn set(&self, answer: Answer) {
        *self.answer.lock().unwrap() = answer;
    }

    pub fn set_delay(&self, delay: Duration) {
        *self.delay.lock().unwrap() = delay;
    }
}

fn reply(req: &Message, answer: Answer) -> Option<Vec<u8>> {
    let mut resp = Message::new(req.id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = true;
    resp.metadata.recursion_available = true;
    match answer {
        Answer::Silent => return None,
        Answer::NxDomain => resp.metadata.response_code = ResponseCode::NXDomain,
        Answer::Address(_) | Answer::Cname(..) => {
            resp.metadata.response_code = ResponseCode::NoError
        }
    }
    for q in &req.queries {
        resp.add_query(q.clone());
        if q.query_type() != RecordType::A {
            continue;
        }
        match answer {
            Answer::Address(ip) => {
                resp.add_answer(Record::from_rdata(q.name().clone(), 300, RData::A(A(ip))));
            }
            Answer::Cname(target, ip) => {
                let target = Name::from_str(target).unwrap();
                resp.add_answer(Record::from_rdata(
                    q.name().clone(),
                    300,
                    RData::CNAME(CNAME(target.clone())),
                ));
                resp.add_answer(Record::from_rdata(target, 300, RData::A(A(ip))));
            }
            Answer::NxDomain | Answer::Silent => {}
        }
    }
    Some(resp.to_bytes().unwrap())
}
