//! Tokens, sessions, passkey challenges and the session address against the
//! real binary and its SQLite database:
//! - an API token's key is shown once, at creation, and never again;
//! - a listed session id cannot be sent back as a session cookie;
//! - anonymous passkey ceremonies cannot pile up without bound;
//! - the address a session records is the TCP peer unless a trusted proxy
//!   names the client.

mod server_process;

use server_process::{Server, TestConfig};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

const PASSWORD: &str = "http-hardening-test";
const API: &str = "/ferrous/api/v1";

struct Reply {
    status: u16,
    head: String,
    json: serde_json::Value,
}

/// One HTTP/1.1 request; `body` is sent as JSON when it is not empty.
fn http(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, &str)], body: &str) -> Reply {
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
    Reply {
        status,
        head: head.to_string(),
        json,
    }
}

fn web_addr(config: &TestConfig) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.web_port)
}

/// A server with auth on and the admin password set. Setup runs on a first
/// start; the restart makes the server read the password from its file.
fn authed_server(extra: &str) -> (TestConfig, Server) {
    let config = TestConfig::with_bind_address(Some("127.0.0.1"), extra, "enabled = true");
    let server = config.start();
    let reply = http(
        web_addr(&config),
        "POST",
        &format!("{API}/auth/setup"),
        &[],
        &serde_json::json!({ "password": PASSWORD }).to_string(),
    );
    assert_eq!(reply.status, 204, "setup failed: {}", reply.json);
    drop(server);
    let server = config.start();
    (config, server)
}

/// The `ferrous_session` cookie a native login sets, sent with `headers`.
fn login(web: SocketAddr, headers: &[(&str, &str)]) -> String {
    let reply = http(
        web,
        "POST",
        &format!("{API}/auth/login"),
        headers,
        &serde_json::json!({ "username": "admin", "password": PASSWORD }).to_string(),
    );
    assert_eq!(reply.status, 200, "login failed: {}", reply.json);
    reply
        .head
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if !name.eq_ignore_ascii_case("set-cookie") {
                return None;
            }
            value
                .trim()
                .strip_prefix("ferrous_session=")?
                .split(';')
                .next()
                .map(str::to_string)
        })
        .unwrap_or_else(|| panic!("no session cookie in:\n{}", reply.head))
}

fn cookie_header(session: &str) -> String {
    format!("ferrous_session={session}")
}

fn sessions(web: SocketAddr, session: &str) -> Vec<serde_json::Value> {
    let cookie = cookie_header(session);
    let reply = http(
        web,
        "GET",
        &format!("{API}/auth/sessions"),
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(reply.status, 200, "{}", reply.json);
    reply.json.as_array().unwrap().clone()
}

#[test]
fn test_updating_an_api_token_never_returns_its_key() {
    let (config, _server) = authed_server("");
    let web = web_addr(&config);
    let cookie = cookie_header(&login(web, &[]));

    let created = http(
        web,
        "POST",
        &format!("{API}/api-tokens"),
        &[("Cookie", &cookie)],
        r#"{"name":"homelab"}"#,
    );
    assert_eq!(created.status, 201, "{}", created.json);
    let key = created.json["token"].as_str().unwrap().to_string();
    let id = created.json["id"].as_i64().unwrap();

    let renamed = http(
        web,
        "PUT",
        &format!("{API}/api-tokens/{id}"),
        &[("Cookie", &cookie)],
        r#"{"name":"homelab-renamed"}"#,
    );
    assert_eq!(renamed.status, 200, "{}", renamed.json);
    assert!(renamed.json["token"].is_null(), "{}", renamed.json);

    // The key itself keeps working after the rename.
    let with_key = http(
        web,
        "GET",
        &format!("{API}/api-tokens"),
        &[("X-Api-Key", &key)],
        "",
    );
    assert_eq!(with_key.status, 200, "{}", with_key.json);
}

#[test]
fn test_a_listed_session_id_is_not_a_session_cookie() {
    let (config, _server) = authed_server("");
    let web = web_addr(&config);
    let session = login(web, &[]);

    let listed = sessions(web, &session);
    assert_eq!(listed.len(), 1, "{listed:?}");
    let id = listed[0]["id"].as_str().unwrap();
    assert_ne!(id, session, "the list shows the cookie value itself");

    let cookie = cookie_header(id);
    let reply = http(
        web,
        "GET",
        &format!("{API}/auth/sessions"),
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(reply.status, 401, "a listed id worked as a cookie");
}

#[test]
fn test_a_listed_session_can_still_be_revoked() {
    let (config, _server) = authed_server("");
    let web = web_addr(&config);
    let mine = login(web, &[]);
    let other = login(web, &[("User-Agent", "other-device")]);
    let third = login(web, &[("User-Agent", "third-device")]);

    let listed = sessions(web, &mine);
    let other_id = listed
        .iter()
        .find(|s| s["user_agent"] == "other-device")
        .and_then(|s| s["id"].as_str())
        .unwrap()
        .to_string();
    let cookie = cookie_header(&mine);
    let reply = http(
        web,
        "DELETE",
        &format!("{API}/auth/sessions/{other_id}"),
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(reply.status, 204, "{}", reply.json);

    let other_cookie = cookie_header(&other);
    let reply = http(
        web,
        "GET",
        &format!("{API}/auth/sessions"),
        &[("Cookie", &other_cookie)],
        "",
    );
    assert_eq!(reply.status, 401, "the revoked session still works");

    // A client that kept the session's own token can still name it by that.
    let reply = http(
        web,
        "DELETE",
        &format!("{API}/auth/sessions/{third}"),
        &[("Cookie", &cookie)],
        "",
    );
    assert_eq!(reply.status, 204, "{}", reply.json);
    let third_cookie = cookie_header(&third);
    let reply = http(
        web,
        "GET",
        &format!("{API}/auth/sessions"),
        &[("Cookie", &third_cookie)],
        "",
    );
    assert_eq!(
        reply.status, 401,
        "the session revoked by token still works"
    );
    assert_eq!(sessions(web, &mine).len(), 1);
}

#[test]
fn test_anonymous_passkey_challenges_are_capped() {
    let config = TestConfig::with_bind_address(
        Some("127.0.0.1"),
        "",
        "enabled = false\n\n[auth.webauthn]\nrp_id = \"localhost\"\nrp_origin = \"http://localhost\"",
    );
    let _server = config.start();
    let web = web_addr(&config);

    let mut issued = 0;
    let mut refused = 0;
    for _ in 0..1100 {
        let reply = http(
            web,
            "POST",
            &format!("{API}/auth/webauthn/discoverable/start"),
            &[],
            "",
        );
        match reply.status {
            200 => issued += 1,
            429 => refused += 1,
            other => panic!("unexpected status {other}: {}", reply.json),
        }
    }
    assert!(issued <= 1024, "{issued} challenges were issued");
    assert!(refused > 0, "no start was refused");
}

#[test]
fn test_session_address_ignores_forwarding_headers_from_an_untrusted_peer() {
    let (config, _server) = authed_server("trusted_proxies = []");
    let web = web_addr(&config);
    let session = login(web, &[("X-Forwarded-For", "203.0.113.9")]);

    assert_eq!(sessions(web, &session)[0]["ip_address"], "127.0.0.1");
}

#[test]
fn test_session_address_is_the_peer_without_forwarding_headers() {
    let (config, _server) = authed_server("");
    let web = web_addr(&config);
    let session = login(web, &[]);

    assert_eq!(sessions(web, &session)[0]["ip_address"], "127.0.0.1");
}

#[test]
fn test_session_address_names_the_client_behind_a_trusted_proxy() {
    // The loopback is a trusted proxy by default.
    let (config, _server) = authed_server("");
    let web = web_addr(&config);
    let session = login(web, &[("X-Forwarded-For", "203.0.113.9")]);

    assert_eq!(sessions(web, &session)[0]["ip_address"], "203.0.113.9");
}

/// The Pi-hole sid from `POST /api/auth`.
fn pihole_login(web: SocketAddr) -> String {
    let reply = http(
        web,
        "POST",
        "/api/auth",
        &[],
        &serde_json::json!({ "password": PASSWORD }).to_string(),
    );
    assert_eq!(reply.status, 200, "Pi-hole login failed: {}", reply.json);
    reply.json["session"]["sid"].as_str().unwrap().to_string()
}

fn pihole_sessions(web: SocketAddr, sid: &str) -> Reply {
    http(web, "GET", "/api/auth/sessions", &[("X-FTL-SID", sid)], "")
}

#[test]
fn test_pihole_sessions_still_list_revoke_and_log_out() {
    let (config, _server) = authed_server("pihole_compat = true");
    let web = web_addr(&config);
    let mine = pihole_login(web);
    let other = pihole_login(web);

    // GET /api/auth echoes the sid the client presented, as FTL does.
    let reply = http(web, "GET", "/api/auth", &[("X-FTL-SID", &mine)], "");
    assert_eq!(reply.status, 200, "{}", reply.json);
    assert_eq!(
        reply.json["session"]["sid"],
        mine.as_str(),
        "{}",
        reply.json
    );

    let listed = pihole_sessions(web, &mine);
    assert_eq!(listed.status, 200, "{}", listed.json);
    let entries = listed.json["sessions"].as_array().unwrap();
    assert_eq!(entries.len(), 2, "{}", listed.json);
    assert_eq!(
        entries
            .iter()
            .filter(|s| s["current_session"] == true)
            .count(),
        1,
        "{}",
        listed.json
    );
    let other_number = entries
        .iter()
        .find(|s| s["current_session"] == false)
        .and_then(|s| s["id"].as_i64())
        .unwrap();

    let reply = http(
        web,
        "DELETE",
        &format!("/api/auth/session/{other_number}"),
        &[("X-FTL-SID", &mine)],
        "",
    );
    assert_eq!(reply.status, 204, "{}", reply.json);
    assert_eq!(pihole_sessions(web, &other).status, 401);

    let reply = http(web, "DELETE", "/api/auth", &[("X-FTL-SID", &mine)], "");
    assert_eq!(reply.status, 204, "{}", reply.json);
    assert_eq!(pihole_sessions(web, &mine).status, 401);
}
