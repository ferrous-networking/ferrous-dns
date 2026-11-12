//! Filtering right after a start, against the real binary. A blocklist
//! source is added through the API, as the dashboard adds it, and the server
//! is then started again:
//!
//! - a restart filters its first answer, without waiting for the list's host;
//! - the list stays in force when its host fails at start;
//! - a start with no copy of the list waits for the download before it answers;
//! - a shutdown signal during that wait closes the database and exits.

mod server_process;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use server_process::{is_refused, server_log, wait_for_exit, FakeUpstream, Server, TestConfig};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// The one name on the list.
const LISTED: &str = "ads.startup.example";
const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
/// What a blocked A query answers under the default `null_ip` block mode.
const BLOCKED: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
/// Longer than any start takes, so an answer before it did not wait for the host.
const SLOW_HOST: Duration = Duration::from_secs(10);

/// The fake upstream's answer: `UPSTREAM_IP` for every A query.
fn reply(request: &Message) -> Message {
    let mut response = Message::new(request.id, MessageType::Response, OpCode::Query);
    response.metadata.recursion_desired = true;
    response.metadata.recursion_available = true;
    response.metadata.response_code = ResponseCode::NoError;
    for query in &request.queries {
        response.add_query(query.clone());
        if query.query_type() == RecordType::A {
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                300,
                RData::A(A(UPSTREAM_IP)),
            ));
        }
    }
    response
}

/// How the list host answers a download.
#[derive(Clone, Copy)]
enum Host {
    /// Sends the list after a delay.
    Serves(Duration),
    /// Keeps the connection open and never answers.
    Hangs,
    /// Closes the connection unanswered, so the download fails.
    Fails,
}

/// An HTTP host on 127.0.0.1 that serves a list holding `LISTED`.
struct ListHost {
    url: String,
    behaviour: Arc<Mutex<Host>>,
}

impl ListHost {
    fn spawn() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/list.txt", listener.local_addr().unwrap());
        let behaviour = Arc::new(Mutex::new(Host::Serves(Duration::ZERO)));
        let current = Arc::clone(&behaviour);
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let host = *current.lock().unwrap();
                std::thread::spawn(move || answer_download(stream, host));
            }
        });
        Self { url, behaviour }
    }

    fn set(&self, host: Host) {
        *self.behaviour.lock().unwrap() = host;
    }
}

fn answer_download(mut stream: TcpStream, host: Host) {
    let delay = match host {
        Host::Serves(delay) => delay,
        Host::Hangs => {
            sleep(Duration::from_secs(120));
            return;
        }
        Host::Fails => return,
    };
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(len) => request.extend_from_slice(&buf[..len]),
        }
    }
    sleep(delay);
    let body = format!("{LISTED}\n");
    let _ = write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
}

fn a_query(name: &str) -> Vec<u8> {
    let mut query = Message::new(0x4242, MessageType::Query, OpCode::Query);
    query.metadata.recursion_desired = true;
    query.add_query(Query::query(
        Name::from_str(&format!("{name}.")).unwrap(),
        RecordType::A,
    ));
    query.to_bytes().unwrap()
}

fn addresses(answer: &Message) -> Vec<IpAddr> {
    answer
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            _ => None,
        })
        .collect()
}

/// Asks a running server for `name A` over UDP.
fn ask(dns_port: u16, name: &str) -> Vec<IpAddr> {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let query = a_query(name);
    let mut buf = [0u8; 4096];
    for _ in 0..5 {
        socket.send_to(&query, ("127.0.0.1", dns_port)).unwrap();
        if let Ok(len) = socket.recv(&mut buf) {
            return addresses(&Message::from_vec(&buf[..len]).unwrap());
        }
    }
    panic!("the server never answered {name}");
}

/// Adds a blocklist source through the API. The call returns once the block
/// filter has been rebuilt with the list.
fn add_blocklist_source(web_port: u16, url: &str) {
    let body = serde_json::json!({ "name": "startup", "url": url }).to_string();
    let mut stream = TcpStream::connect(("127.0.0.1", web_port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let request = format!(
        "POST /ferrous/api/v1/blocklist-sources HTTP/1.1\r\nHost: 127.0.0.1:{web_port}\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    assert!(
        response.starts_with("HTTP/1.1 201"),
        "adding the source failed: {response}"
    );
}

/// A config whose database holds a blocklist source served by `host`, as left
/// by a server that downloaded the list and then stopped.
fn seeded(upstream: &FakeUpstream, host: &ListHost) -> TestConfig {
    let config = TestConfig::filtering(upstream.addr);
    let server = config.start();
    add_blocklist_source(config.web_port, &host.url);
    assert_eq!(
        ask(config.dns_port, LISTED),
        [BLOCKED],
        "the source blocks once added"
    );
    drop(server);
    config
}

/// Starts the server again, and returns it with the first answer it gives
/// for `LISTED` and how long after the spawn that answer came.
fn restart(config: &TestConfig) -> (Server, Vec<IpAddr>, Duration) {
    let started = Instant::now();
    let mut server = Server {
        child: config.spawn_logged(config.command()),
    };
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let query = a_query(LISTED);
    let mut buf = [0u8; 4096];
    while started.elapsed() < Duration::from_secs(60) {
        if let Some(status) = server.child.try_wait().unwrap() {
            panic!(
                "server exited with {status}:\n{}",
                server_log(config.dir.path())
            );
        }
        let _ = socket.send_to(&query, ("127.0.0.1", config.dns_port));
        if let Ok(len) = socket.recv(&mut buf) {
            let first = addresses(&Message::from_vec(&buf[..len]).unwrap());
            return (server, first, started.elapsed());
        }
    }
    panic!(
        "the server never answered:\n{}",
        server_log(config.dir.path())
    );
}

fn wait_for_log(config: &TestConfig, line: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !server_log(config.dir.path()).contains(line) {
        assert!(
            Instant::now() < deadline,
            "no {line:?} in the log:\n{}",
            server_log(config.dir.path())
        );
        sleep(Duration::from_millis(50));
    }
}

#[test]
fn test_a_restart_filters_from_its_first_answer_without_waiting_for_the_host() {
    let upstream = FakeUpstream::spawn(reply);
    let host = ListHost::spawn();
    let config = seeded(&upstream, &host);

    host.set(Host::Serves(SLOW_HOST));
    let (_server, first, after) = restart(&config);
    assert_eq!(
        first,
        [BLOCKED],
        "the first answer after a restart is filtered:\n{}",
        server_log(config.dir.path())
    );
    assert!(
        after < SLOW_HOST,
        "the restart waited {after:?} for the list host:\n{}",
        server_log(config.dir.path())
    );
}

#[test]
fn test_lists_stay_in_force_when_their_host_fails_at_start() {
    let upstream = FakeUpstream::spawn(reply);
    let host = ListHost::spawn();
    let config = seeded(&upstream, &host);

    host.set(Host::Fails);
    let (_server, first, _) = restart(&config);
    assert_eq!(
        first,
        [BLOCKED],
        "the list is in force although its host fails:\n{}",
        server_log(config.dir.path())
    );

    wait_for_log(&config, "keeping the previous download");
    assert_eq!(
        ask(config.dns_port, LISTED),
        [BLOCKED],
        "the failed download after the start keeps the list"
    );
}

#[test]
fn test_a_start_without_copies_waits_for_the_download() {
    let upstream = FakeUpstream::spawn(reply);
    let host = ListHost::spawn();
    let config = seeded(&upstream, &host);
    let _ = fs::remove_dir_all(config.dir.path().join("lists"));

    let delay = Duration::from_secs(2);
    host.set(Host::Serves(delay));
    let (_server, first, after) = restart(&config);
    assert_eq!(
        first,
        [BLOCKED],
        "the first answer waits for the list:\n{}",
        server_log(config.dir.path())
    );
    assert!(
        after >= delay,
        "answered {after:?} after the start, before the list arrived"
    );
}

#[cfg(unix)]
#[test]
fn test_a_shutdown_during_the_startup_hold_closes_the_database() {
    let upstream = FakeUpstream::spawn(reply);
    let host = ListHost::spawn();
    let config = seeded(&upstream, &host);
    let _ = fs::remove_dir_all(config.dir.path().join("lists"));

    host.set(Host::Hangs);
    let mut server = Server {
        child: config.spawn_logged(config.command()),
    };
    wait_for_log(
        &config,
        "Waiting for the blocklists before opening the listeners",
    );
    assert!(
        is_refused(SocketAddr::from((config.web_host, config.web_port))),
        "the web port stays closed while the lists compile"
    );

    // SAFETY: plain kill(2) on the child this test spawned and still owns.
    assert_eq!(
        unsafe { libc::kill(server.child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    let Some(status) = wait_for_exit(&mut server.child, Duration::from_secs(5)) else {
        panic!(
            "server still running 5 s after SIGTERM during the hold:\n{}",
            server_log(config.dir.path())
        );
    };
    assert!(
        status.success(),
        "server ended with {status} on SIGTERM:\n{}",
        server_log(config.dir.path())
    );
    assert!(
        !config.dir.path().join("ferrous.db-wal").exists(),
        "the WAL survived a SIGTERM during the hold:\n{}",
        server_log(config.dir.path())
    );
}
