//! CNAME cloaking and the CNAME target cache against the real binary. A fake
//! upstream answers two first-party names with CNAME chains, and managed
//! domains are added through the API, as the dashboard adds them:
//!
//! - a chain through a denied name is blocked (CNAME cloaking);
//! - it stays blocked once a block filter rebuild drops the block memo, when
//!   the answer comes from the cache;
//! - a chain's final target is answered from the cache (#325);
//! - an allow on the queried name lifts the block.

mod server_process;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use server_process::TestConfig;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const CLOAKED: &str = "metrics.site.example";
const TRACKER: &str = "x.tracker.example";
const TRACKER_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 9);
const CLEAN: &str = "app.site.example";
const CDN: &str = "lb.cdn.example";
const CDN_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 10);
/// What a blocked A query answers under the default `null_ip` block mode.
const BLOCKED: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// A UDP upstream that answers `CLOAKED` and `CLEAN` with a CNAME chain and
/// anything else with NXDOMAIN, counting what it is asked by lowercase name.
struct FakeUpstream {
    addr: SocketAddr,
    asked: Arc<Mutex<HashMap<String, usize>>>,
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

    fn times_asked(&self, name: &str) -> usize {
        self.asked.lock().unwrap().get(name).copied().unwrap_or(0)
    }
}

fn reply(request: &Message, asked: &Mutex<HashMap<String, usize>>) -> Vec<u8> {
    let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_desired = true;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NXDomain;
    for query in &request.queries {
        response.add_query(query.clone());
        let name = query.name().to_ascii().to_ascii_lowercase();
        let name = name.trim_end_matches('.');
        *asked.lock().unwrap().entry(name.to_string()).or_default() += 1;
        let (target, ip) = match name {
            CLOAKED => (TRACKER, TRACKER_IP),
            CLEAN => (CDN, CDN_IP),
            _ => continue,
        };
        response.metadata.response_code = ResponseCode::NoError;
        let target = Name::from_str(&format!("{target}.")).unwrap();
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            300,
            RData::CNAME(CNAME(target.clone())),
        ));
        if query.query_type() == RecordType::A {
            response.add_answer(Record::from_rdata(target, 300, RData::A(A(ip))));
        }
    }
    response.to_bytes().unwrap()
}

/// Asks the server for `name A` over UDP and returns the addresses it answers
/// with. Retries a lost datagram, which only happens while the listener starts.
fn ask(dns_port: u16, name: &str) -> Vec<IpAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut query = Message::new(0x4242, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_str(&format!("{name}.")).unwrap(),
        RecordType::A,
    ));
    let query = query.to_bytes().unwrap();
    let mut buf = [0u8; 4096];
    for _ in 0..5 {
        socket.send_to(&query, ("127.0.0.1", dns_port)).unwrap();
        if let Ok(len) = socket.recv(&mut buf) {
            let answer = Message::from_vec(&buf[..len]).unwrap();
            return answer
                .answers
                .iter()
                .filter_map(|record| match &record.data {
                    RData::A(a) => Some(IpAddr::V4(a.0)),
                    _ => None,
                })
                .collect();
        }
    }
    panic!("the server never answered {name}");
}

/// Adds a managed domain through the API, as the dashboard does. The call
/// returns once the block filter has been rebuilt with it.
fn add_managed_domain(web_port: u16, domain: &str, action: &str) {
    let body = serde_json::json!({
        "name": format!("live-{action}-{domain}"),
        "domain": domain,
        "action": action,
        "group_id": 1,
    })
    .to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", web_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let request = format!(
        "POST /ferrous/api/v1/managed-domains HTTP/1.1\r\nHost: 127.0.0.1:{web_port}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "adding {action} {domain} failed: {response}"
    );
}

#[test]
fn test_cname_cloaking_and_the_target_cache_on_the_real_server() {
    let upstream = FakeUpstream::spawn();
    let config = TestConfig::filtering(upstream.addr);
    let _server = config.start();

    add_managed_domain(config.web_port, TRACKER, "deny");
    assert_eq!(
        ask(config.dns_port, CLOAKED),
        [BLOCKED],
        "a chain through a denied name is blocked"
    );

    // The rebuild drops the block memo, so the next answer is the cached one.
    add_managed_domain(config.web_port, "unrelated.example", "deny");
    assert_eq!(
        ask(config.dns_port, CLOAKED),
        [BLOCKED],
        "the cached answer is still blocked"
    );
    assert_eq!(
        upstream.times_asked(CLOAKED),
        1,
        "the second answer came from the cache"
    );

    assert_eq!(ask(config.dns_port, CLEAN), [IpAddr::V4(CDN_IP)]);
    assert_eq!(ask(config.dns_port, CDN), [IpAddr::V4(CDN_IP)]);
    assert_eq!(
        upstream.times_asked(CDN),
        0,
        "the chain's target is answered from the cache"
    );

    add_managed_domain(config.web_port, CLOAKED, "allow");
    assert_eq!(
        ask(config.dns_port, CLOAKED),
        [IpAddr::V4(TRACKER_IP)],
        "an allow on the queried name lifts the block"
    );
}
