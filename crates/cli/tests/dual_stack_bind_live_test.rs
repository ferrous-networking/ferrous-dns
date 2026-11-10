//! `[server] bind_address = "auto"`, the default, against the real binary:
//! DNS and the web server answer IPv4 and IPv6 clients, while a config that
//! names `0.0.0.0` keeps listening on IPv4 only.
#![cfg(target_os = "linux")]

mod common;
mod server_process;

use common::skip_without_dual_stack;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use server_process::{accepts_within, http_status, is_refused, TestConfig};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

const V4: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const V6: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);
const QUERY_ID: u16 = 0x375;

/// A private-range PTR query, which `block_private_ptr` (on by default)
/// answers without an upstream.
fn private_ptr_query() -> Vec<u8> {
    let mut query = Query::new();
    query.set_name(Name::from_ascii("1.1.168.192.in-addr.arpa.").unwrap());
    query.set_query_type(RecordType::PTR);
    query.set_query_class(DNSClass::IN);
    let mut message = Message::new(QUERY_ID, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(query);
    message.to_vec().unwrap()
}

fn udp_answers(server: SocketAddr) -> bool {
    let local: SocketAddr = match server.ip() {
        IpAddr::V4(_) => "127.0.0.1:0".parse().unwrap(),
        IpAddr::V6(_) => "[::1]:0".parse().unwrap(),
    };
    let socket = UdpSocket::bind(local).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.send_to(&private_ptr_query(), server).unwrap();
    let mut buf = [0u8; 512];
    match socket.recv_from(&mut buf) {
        Ok((len, _)) => Message::from_vec(&buf[..len]).is_ok_and(|reply| reply.id == QUERY_ID),
        Err(_) => false,
    }
}

fn assert_serves(config: &TestConfig, ip: IpAddr) {
    let dns = SocketAddr::new(ip, config.dns_port);
    assert!(
        accepts_within(dns, Duration::from_secs(10)),
        "DNS over TCP on {dns}"
    );
    assert!(udp_answers(dns), "DNS over UDP on {dns}");
    assert_eq!(
        http_status(
            SocketAddr::new(ip, config.web_port),
            "/ferrous/api/v1/health"
        ),
        200,
        "web on {ip}"
    );
}

#[test]
fn test_auto_serves_dns_and_web_on_ipv4_and_ipv6() {
    if skip_without_dual_stack("test_auto_serves_dns_and_web_on_ipv4_and_ipv6") {
        return;
    }
    let config = TestConfig::with_bind_address(Some("auto"), "", "enabled = false");
    let _server = config.start();

    assert_serves(&config, V4);
    assert_serves(&config, V6);
}

#[test]
fn test_missing_bind_address_serves_both_families() {
    if skip_without_dual_stack("test_missing_bind_address_serves_both_families") {
        return;
    }
    let config = TestConfig::with_bind_address(None, "", "enabled = false");
    let _server = config.start();

    assert_serves(&config, V4);
    assert_serves(&config, V6);
}

#[test]
fn test_ipv4_bind_address_still_refuses_ipv6() {
    if skip_without_dual_stack("test_ipv4_bind_address_still_refuses_ipv6") {
        return;
    }
    let config = TestConfig::with_bind_address(Some("0.0.0.0"), "", "enabled = false");
    let _server = config.start();

    assert_serves(&config, V4);
    assert!(
        is_refused(SocketAddr::new(V6, config.dns_port)),
        "DNS over TCP on ::1"
    );
    assert!(
        is_refused(SocketAddr::new(V6, config.web_port)),
        "web on ::1"
    );
}
