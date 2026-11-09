//! The web server on a dual-stack `[::]` bind against the real binary: an
//! IPv4 client reaches it as `::ffff:a.b.c.d`, and everything behind the web
//! listener must see the plain IPv4 address, as the DNS listeners already do.
#![cfg(target_os = "linux")]

mod common;
mod server_process;

use server_process::{Server, TestConfig};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

const PASSWORD: &str = "dual-stack-peer-test";

/// Status and JSON body of a plain HTTP/1.1 request.
fn http_json(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (u16, serde_json::Value) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let (head, payload) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("not an HTTP response: {response}"));
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line: {head}"));
    let json = serde_json::from_str(payload).unwrap_or(serde_json::Value::Null);
    (status, json)
}

fn skip_without_dual_stack(test: &str) -> bool {
    if common::dual_stack_loopback_available() {
        return false;
    }
    eprintln!("skipping {test}: no dual-stack loopback available");
    true
}

fn pihole_server_on_dual_stack(auth: &str) -> TestConfig {
    TestConfig::with_bind_address(Some("[::]"), "pihole_compat = true", auth)
}

fn client_info_remote_addr(web: SocketAddr) -> String {
    let (status, json) = http_json(web, "GET", "/api/info/client", &[], "");
    assert_eq!(status, 200, "{json}");
    json["remote_addr"].as_str().unwrap().to_string()
}

#[test]
fn test_pihole_client_info_reports_an_ipv4_peer_on_a_dual_stack_listener() {
    if skip_without_dual_stack(
        "test_pihole_client_info_reports_an_ipv4_peer_on_a_dual_stack_listener",
    ) {
        return;
    }
    let config = pihole_server_on_dual_stack("enabled = false");
    let _server = config.start();

    let web = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.web_port);
    assert_eq!(client_info_remote_addr(web), "127.0.0.1");
}

#[test]
fn test_ipv6_peer_is_reported_unchanged() {
    if skip_without_dual_stack("test_ipv6_peer_is_reported_unchanged") {
        return;
    }
    let config = pihole_server_on_dual_stack("enabled = false");
    let _server = config.start();

    let web = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), config.web_port);
    assert_eq!(client_info_remote_addr(web), "::1");
}

/// Sets the admin password through the setup endpoint, then restarts so the
/// server reads it: a running server keeps the `[auth]` it started with.
fn start_with_password(config: &TestConfig) -> Server {
    let web = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.web_port);
    let server = config.start();
    let (status, json) = http_json(
        web,
        "POST",
        "/ferrous/api/v1/auth/setup",
        &[],
        &serde_json::json!({ "password": PASSWORD }).to_string(),
    );
    assert_eq!(status, 204, "setup failed: {json}");
    drop(server);
    config.start()
}

#[test]
fn test_pihole_session_records_an_ipv4_peer_on_a_dual_stack_listener() {
    if skip_without_dual_stack("test_pihole_session_records_an_ipv4_peer_on_a_dual_stack_listener")
    {
        return;
    }
    let config = pihole_server_on_dual_stack("enabled = true");
    let _server = start_with_password(&config);

    let web = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.web_port);
    let (status, json) = http_json(
        web,
        "POST",
        "/api/auth",
        &[],
        &serde_json::json!({ "password": PASSWORD }).to_string(),
    );
    assert_eq!(status, 200, "login failed: {json}");
    let sid = json["session"]["sid"].as_str().unwrap().to_string();

    let (status, json) = http_json(web, "GET", "/api/auth/sessions", &[("X-FTL-SID", &sid)], "");
    assert_eq!(status, 200, "{json}");
    assert_eq!(json["sessions"][0]["remote_addr"], "127.0.0.1", "{json}");
}
