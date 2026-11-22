//! Upstream addresses this host has no route to (#402). In a container
//! without IPv6, an upstream hostname's AAAA addresses can never be dialed.
//! They are labelled `no_route` and left out of the server's status, instead
//! of turning it `Partial` and failing a health check every interval. A
//! seccomp filter takes IPv6 away from the binary, as on a kernel without it.
#![cfg(target_os = "linux")]

mod server_process;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::Value;
use server_process::{
    accepts_within, http_get, server_log, skip_without_seccomp, FakeUpstream, TestConfig,
};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// The upstream's hostname, which resolves to the loopback in both families.
const UPSTREAM_NAME: &str = "up.ferrous-test.net";
/// What every other A query is answered with.
const ANSWER_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The LAN router and the upstream in one: `UPSTREAM_NAME` gets A 127.0.0.1
/// and AAAA ::1, any other A query gets `ANSWER_IP`.
fn reply(request: &Message) -> Message {
    let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_desired = request.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NoError;
    for query in &request.queries {
        response.add_query(query.clone());
        let is_upstream = query
            .name()
            .to_ascii()
            .trim_end_matches('.')
            .eq_ignore_ascii_case(UPSTREAM_NAME);
        let rdata = match (query.query_type(), is_upstream) {
            (RecordType::A, true) => RData::A(A(Ipv4Addr::LOCALHOST)),
            (RecordType::AAAA, true) => RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
            (RecordType::A, false) => RData::A(A(ANSWER_IP)),
            _ => continue,
        };
        response.add_answer(Record::from_rdata(query.name().clone(), 300, rdata));
    }
    response
}

/// A server whose one upstream is `udp://UPSTREAM_NAME:<port>`, looked up
/// through `upstream` as its `local_dns_server`.
fn config(upstream: SocketAddr) -> TestConfig {
    TestConfig::with_dns(&format!(
        "upstream_servers = [\"udp://{UPSTREAM_NAME}:{port}\"]\n\
         local_dns_server = \"{upstream}\"\n\
         malware_detection_enabled = false\n\
         dnssec_mode = \"Off\"",
        port = upstream.port()
    ))
}

/// The upstream's group in `GET /upstream/health/detail`.
fn upstream_group(config: &TestConfig) -> Value {
    let web = SocketAddr::new(LOCALHOST, config.web_port);
    let (status, body) = http_get(web, "/ferrous/api/v1/upstream/health/detail");
    assert_eq!(status, 200, "{body}");
    let groups: Vec<Value> = serde_json::from_str(&body).unwrap();
    assert_eq!(groups.len(), 1, "{body}");
    groups.into_iter().next().unwrap()
}

/// The row for `address` in `group`'s per-IP breakdown.
fn endpoint<'a>(group: &'a Value, address: &str) -> &'a Value {
    group["resolved"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["address"] == address)
        .unwrap_or_else(|| panic!("no {address} row in {group:#}"))
}

/// Waits until the IPv4 address has passed its health checks: by then the
/// IPv6 one has been checked as many times.
fn group_once_ipv4_is_healthy(config: &TestConfig, ipv4: &str) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let group = upstream_group(config);
        if endpoint(&group, ipv4)["status"] == "Healthy" {
            return group;
        }
        assert!(
            Instant::now() < deadline,
            "{ipv4} never turned Healthy: {group:#}\n{}",
            server_log(config.dir.path())
        );
        sleep(Duration::from_millis(100));
    }
}

/// The A address `server` answers for `name` over UDP.
fn resolve_a(server: SocketAddr, name: &str) -> Option<Ipv4Addr> {
    let mut query = Message::new(0x402, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(Name::from_ascii(name).unwrap(), RecordType::A));
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.send_to(&query.to_vec().unwrap(), server).unwrap();
    let mut buf = [0u8; 512];
    let (len, _) = socket.recv_from(&mut buf).ok()?;
    Message::from_vec(&buf[..len])
        .ok()?
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::A(A(ip)) => Some(*ip),
            _ => None,
        })
}

#[test]
fn test_ipv6_addresses_without_a_route_are_labelled_and_left_out_of_the_status() {
    if skip_without_seccomp(
        "test_ipv6_addresses_without_a_route_are_labelled_and_left_out_of_the_status",
    ) {
        return;
    }
    let upstream = FakeUpstream::spawn(reply);
    let config = config(upstream.addr);
    let _server = config.start_without_ipv6();
    let ipv4 = upstream.addr.to_string();
    let ipv6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), upstream.addr.port()).to_string();

    let group = group_once_ipv4_is_healthy(&config, &ipv4);

    let row = endpoint(&group, &ipv6);
    assert_eq!(row["no_route"], true, "{group:#}");
    assert_eq!(row["status"], "Unhealthy", "{group:#}");
    assert_eq!(endpoint(&group, &ipv4)["no_route"], false, "{group:#}");
    assert_eq!(group["status"], "Healthy", "{group:#}");

    let dns = SocketAddr::new(LOCALHOST, config.dns_port);
    assert!(accepts_within(dns, Duration::from_secs(10)));
    assert_eq!(resolve_a(dns, "answer.ferrous-test.net."), Some(ANSWER_IP));
    let log = server_log(config.dir.path());
    assert!(!log.contains("Health check: FAILED"), "{log}");
}
