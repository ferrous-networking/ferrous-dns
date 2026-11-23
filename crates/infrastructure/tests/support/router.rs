//! A LAN router for the upstream hostname tests, whose answers can be changed
//! mid-test.
#![allow(dead_code)]

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};
use std::collections::{HashMap, VecDeque};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use tokio::net::UdpSocket;

/// A name's A addresses, handed out in turn, and their TTL.
type Answers = HashMap<String, (VecDeque<Ipv4Addr>, u32)>;
/// A name's AAAA addresses, all in each answer, and their TTL.
type Ipv6Answers = HashMap<String, (Vec<Ipv6Addr>, u32)>;

/// A name maps to its A addresses, handed out one per query in turn, and to
/// its AAAA addresses; a name it does not know gets NXDOMAIN. A name with
/// addresses of one family only gets an empty answer for the other.
#[derive(Clone, Default)]
pub struct Router {
    answers: Arc<Mutex<Answers>>,
    ipv6_answers: Arc<Mutex<Ipv6Answers>>,
}

impl Router {
    pub fn set(&self, name: &str, ip: Ipv4Addr, ttl: u32) {
        self.rotate(name, &[ip], ttl);
    }

    /// Answers each A query for `name` with the next of `ips`.
    pub fn rotate(&self, name: &str, ips: &[Ipv4Addr], ttl: u32) {
        self.answers
            .lock()
            .unwrap()
            .insert(format!("{name}."), (ips.iter().copied().collect(), ttl));
    }

    /// Answers each AAAA query for `name` with all of `ips`.
    pub fn set_ipv6(&self, name: &str, ips: &[Ipv6Addr], ttl: u32) {
        self.ipv6_answers
            .lock()
            .unwrap()
            .insert(format!("{name}."), (ips.to_vec(), ttl));
    }

    pub fn forget(&self, name: &str) {
        self.answers.lock().unwrap().remove(&format!("{name}."));
        self.ipv6_answers
            .lock()
            .unwrap()
            .remove(&format!("{name}."));
    }

    pub async fn spawn(&self) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let answers = Arc::clone(&self.answers);
        let ipv6_answers = Arc::clone(&self.ipv6_answers);
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
                let ipv4 = answers.lock().unwrap().get_mut(&name).map(|(ips, ttl)| {
                    let ip = ips[0];
                    if q.query_type() == RecordType::A {
                        ips.rotate_left(1);
                    }
                    (ip, *ttl)
                });
                let ipv6 = ipv6_answers.lock().unwrap().get(&name).cloned();
                if ipv4.is_none() && ipv6.is_none() {
                    resp.metadata.response_code = ResponseCode::NXDomain;
                } else {
                    resp.metadata.response_code = ResponseCode::NoError;
                }
                let records: Vec<(RData, u32)> = match (q.query_type(), ipv4, ipv6) {
                    (RecordType::A, Some((ip, ttl)), _) => vec![(RData::A(A(ip)), ttl)],
                    (RecordType::AAAA, _, Some((ips, ttl))) => ips
                        .into_iter()
                        .map(|ip| (RData::AAAA(AAAA(ip)), ttl))
                        .collect(),
                    _ => Vec::new(),
                };
                for (rdata, ttl) in records {
                    resp.add_answer(Record::from_rdata(q.name().clone(), ttl, rdata));
                }
                let _ = socket.send_to(&resp.to_vec().unwrap(), peer).await;
            }
        });
        addr
    }
}
