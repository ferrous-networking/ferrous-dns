//! Every UDP send path of the real binary, on each socket family a listener
//! can have: an IPv4 bind (AF_INET), and `"auto"` (dual-stack AF_INET6) with
//! IPv4 and IPv6 clients. IPv4 clients query 127.0.0.2 on a `connect`ed
//! socket, which drops any answer that does not come back from that address:
//! without pktinfo the kernel would answer from 127.0.0.1.
#![cfg(target_os = "linux")]

mod common;
mod server_process;

use common::{dual_stack_loopback_available, ipv6_loopback_available};
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use server_process::{accepts_within, server_log, Server, TestConfig};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ANSWER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TXT_ANSWER: &str = "ferrous";

/// A UDP upstream that answers every A query with `ANSWER` and every TXT
/// query with `TXT_ANSWER`, counting what it is asked by name and type.
struct FakeUpstream {
    addr: SocketAddr,
    asked: Arc<Mutex<HashMap<(String, RecordType), usize>>>,
}

impl FakeUpstream {
    fn spawn() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let asked = Arc::new(Mutex::new(HashMap::new()));
        let counts = Arc::clone(&asked);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf) {
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                let _ = socket.send_to(&reply(&request, &counts), peer);
            }
        });
        Self { addr, asked }
    }

    fn times_asked(&self, name: &str, record_type: RecordType) -> usize {
        self.asked
            .lock()
            .unwrap()
            .get(&(name.to_string(), record_type))
            .copied()
            .unwrap_or(0)
    }
}

fn reply(request: &Message, asked: &Mutex<HashMap<(String, RecordType), usize>>) -> Vec<u8> {
    let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_desired = true;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NoError;
    for query in &request.queries {
        response.add_query(query.clone());
        let name = query.name().to_ascii().to_ascii_lowercase();
        let name = name.trim_end_matches('.').to_string();
        *asked
            .lock()
            .unwrap()
            .entry((name, query.query_type()))
            .or_default() += 1;
        let data = match query.query_type() {
            RecordType::A => RData::A(A(ANSWER)),
            RecordType::TXT => RData::TXT(TXT::new(vec![TXT_ANSWER.to_string()])),
            _ => continue,
        };
        response.add_answer(Record::from_rdata(query.name().clone(), 300, data));
    }
    response.to_bytes().unwrap()
}

/// Where a test's server listens and how its client reaches it.
struct Arm {
    name: &'static str,
    bind: &'static str,
    /// The address the client sends to.
    target: IpAddr,
    /// The client's own bind.
    local: &'static str,
}

const ARMS: [Arm; 3] = [
    Arm {
        name: "0.0.0.0, IPv4 client",
        bind: "0.0.0.0",
        target: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        local: "127.0.0.1:0",
    },
    Arm {
        name: "auto, IPv4 client",
        bind: "auto",
        target: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
        local: "127.0.0.1:0",
    },
    Arm {
        name: "auto, IPv6 client",
        bind: "auto",
        target: IpAddr::V6(Ipv6Addr::LOCALHOST),
        local: "[::1]:0",
    },
];

impl Arm {
    /// The `auto` arms need a `[::]` socket that receives IPv4, and the IPv6
    /// arm the IPv6 loopback.
    fn runs_here(&self) -> bool {
        let runs = match (self.bind, self.target) {
            ("auto", IpAddr::V6(_)) => dual_stack_loopback_available() && ipv6_loopback_available(),
            ("auto", _) => dual_stack_loopback_available(),
            _ => true,
        };
        if !runs {
            eprintln!(
                "skipping the {} arm: no dual-stack or IPv6 loopback",
                self.name
            );
        }
        runs
    }

    fn start(&self, upstream: &FakeUpstream) -> (TestConfig, Server) {
        self.start_with(upstream, |_| {})
    }

    /// [`Self::start`] with one runtime worker, so the listener has a single
    /// UDP socket that every client shares.
    fn start_single_worker(&self, upstream: &FakeUpstream) -> (TestConfig, Server) {
        let (config, server) = self.start_with(upstream, |command| {
            command.env("TOKIO_WORKER_THREADS", "1");
        });
        let log = server_log(config.dir.path());
        assert!(log.contains("num_workers=1"), "{}:\n{log}", self.name);
        (config, server)
    }

    fn start_with(
        &self,
        upstream: &FakeUpstream,
        configure: impl FnOnce(&mut Command),
    ) -> (TestConfig, Server) {
        let config = TestConfig::filtering_on(self.bind, upstream.addr);
        let mut command = config.command();
        configure(&mut command);
        let server = config.start_with(command);
        assert!(
            accepts_within(
                SocketAddr::from((Ipv4Addr::LOCALHOST, config.dns_port)),
                Duration::from_secs(10)
            ),
            "{}: DNS listener:\n{}",
            self.name,
            server_log(config.dir.path())
        );
        (config, server)
    }

    /// A client socket that only accepts datagrams from `target`.
    fn client(&self, dns_port: u16) -> UdpSocket {
        let socket = UdpSocket::bind(self.local).unwrap();
        socket.connect((self.target, dns_port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
    }
}

fn query(id: u16, name: &str, record_type: RecordType) -> Vec<u8> {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(
        Name::from_str(&format!("{name}.")).unwrap(),
        record_type,
    ));
    message.to_bytes().unwrap()
}

/// Sends one query on `client` and returns the answer's records, failing
/// when no answer arrives from the address the query went to.
fn ask(arm: &Arm, client: &UdpSocket, id: u16, name: &str, record_type: RecordType) -> Vec<RData> {
    client.send(&query(id, name, record_type)).unwrap();
    let mut buf = [0u8; 4096];
    let len = client.recv(&mut buf).unwrap_or_else(|e| {
        panic!(
            "{}: no answer to {name} {record_type} from {} ({e})",
            arm.name, arm.target
        )
    });
    let reply = Message::from_vec(&buf[..len]).unwrap();
    assert_eq!(reply.id, id, "{}", arm.name);
    reply
        .answers
        .into_iter()
        .map(|record| record.data)
        .collect()
}

fn assert_a_answer(arm: &Arm, answers: &[RData]) {
    assert!(
        answers
            .iter()
            .any(|data| matches!(data, RData::A(a) if a.0 == ANSWER)),
        "{}: {answers:?}",
        arm.name
    );
}

#[test]
fn test_a_miss_is_answered_from_the_queried_address() {
    let upstream = FakeUpstream::spawn();
    for (i, arm) in ARMS.iter().enumerate().filter(|(_, arm)| arm.runs_here()) {
        let (config, _server) = arm.start(&upstream);
        let name = format!("miss{i}.reply-path.example");

        let answers = ask(arm, &arm.client(config.dns_port), 1, &name, RecordType::A);

        assert_a_answer(arm, &answers);
        assert_eq!(
            upstream.times_asked(&name, RecordType::A),
            1,
            "{}",
            arm.name
        );
    }
}

#[test]
fn test_a_cache_hit_is_answered_from_the_queried_address() {
    let upstream = FakeUpstream::spawn();
    for (i, arm) in ARMS.iter().enumerate().filter(|(_, arm)| arm.runs_here()) {
        let (config, _server) = arm.start(&upstream);
        let name = format!("hit{i}.reply-path.example");
        let client = arm.client(config.dns_port);
        ask(arm, &client, 1, &name, RecordType::A);

        let answers = ask(arm, &client, 2, &name, RecordType::A);

        assert_a_answer(arm, &answers);
        // The second answer came from the cache.
        assert_eq!(
            upstream.times_asked(&name, RecordType::A),
            1,
            "{}",
            arm.name
        );
    }
}

#[test]
fn test_a_wire_data_hit_is_answered_from_the_queried_address() {
    let upstream = FakeUpstream::spawn();
    for (i, arm) in ARMS.iter().enumerate().filter(|(_, arm)| arm.runs_here()) {
        let (config, _server) = arm.start(&upstream);
        let name = format!("txt{i}.reply-path.example");
        let client = arm.client(config.dns_port);
        ask(arm, &client, 1, &name, RecordType::TXT);

        let answers = ask(arm, &client, 2, &name, RecordType::TXT);

        assert!(
            answers.iter().any(|data| matches!(data, RData::TXT(_))),
            "{}: {answers:?}",
            arm.name
        );
        assert_eq!(
            upstream.times_asked(&name, RecordType::TXT),
            1,
            "{}",
            arm.name
        );
    }
}

#[test]
fn test_a_burst_wider_than_one_batch_is_fully_answered() {
    const CLIENTS: u16 = 4;
    const PER_CLIENT: u16 = 50;
    let upstream = FakeUpstream::spawn();
    for (i, arm) in ARMS.iter().enumerate().filter(|(_, arm)| arm.runs_here()) {
        // One runtime worker, so one UDP socket: every client's queries share
        // its batches, and one sendmmsg answers several peers.
        let (config, _server) = arm.start_single_worker(&upstream);
        let name = format!("burst{i}.reply-path.example");
        let clients: Vec<_> = (0..CLIENTS).map(|_| arm.client(config.dns_port)).collect();
        ask(arm, &clients[0], 1, &name, RecordType::A);

        // Sent before any answer is read, so the listener drains them in
        // batches of up to 64.
        for (c, client) in (0..).zip(&clients) {
            for n in 0..PER_CLIENT {
                client
                    .send(&query(1000 + c * PER_CLIENT + n, &name, RecordType::A))
                    .unwrap();
            }
        }
        for (c, client) in (0..).zip(&clients) {
            let expected: Vec<u16> = (0..PER_CLIENT).map(|n| 1000 + c * PER_CLIENT + n).collect();
            // Every ID exactly once, to this client: a duplicate or a reply
            // meant for another peer shows up as a mismatch.
            let mut answered = Vec::new();
            let mut buf = [0u8; 4096];
            while answered.len() < expected.len() {
                let Ok(len) = client.recv(&mut buf) else {
                    break;
                };
                let reply = Message::from_vec(&buf[..len]).unwrap();
                answered.push(reply.id);
            }
            answered.sort_unstable();
            assert_eq!(answered, expected, "{}: client {c}", arm.name);
        }
        assert_eq!(
            upstream.times_asked(&name, RecordType::A),
            1,
            "{}",
            arm.name
        );
    }
}
