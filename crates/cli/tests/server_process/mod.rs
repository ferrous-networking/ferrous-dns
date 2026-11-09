//! Helpers for tests that run the real `ferrous-dns` binary.
//!
//! This module is compiled into every integration-test binary that declares
//! `mod server_process;`, so items only one binary uses would otherwise trip
//! dead-code warnings under `-D warnings`.
#![allow(dead_code)]

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// A loopback port free for TCP and UDP alike, since DNS listens on both.
pub fn free_port() -> u16 {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

pub fn wait_for_exit(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        sleep(Duration::from_millis(50));
    }
    None
}

pub fn server_log(dir: &Path) -> String {
    fs::read_to_string(dir.join("server.log")).unwrap_or_default()
}

/// The status code of a plain HTTP/1.1 GET.
pub fn http_status(addr: SocketAddr, path: &str) -> u16 {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // One write: the TLS port's redirect reads a single segment, then closes.
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("not an HTTP response: {response}"))
}

pub fn is_refused(addr: SocketAddr) -> bool {
    matches!(TcpStream::connect(addr), Err(e) if e.kind() == ErrorKind::ConnectionRefused)
}

/// The DNS listener may come up just after the web one.
pub fn accepts_within(addr: SocketAddr, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while TcpStream::connect(addr).is_err() {
        if Instant::now() > deadline {
            return false;
        }
        sleep(Duration::from_millis(50));
    }
    true
}

/// A config file in its own temp dir, for a server with auth off on loopback
/// unless a constructor says otherwise.
pub struct TestConfig {
    pub dir: TempDir,
    pub path: PathBuf,
    pub dns_port: u16,
    pub web_port: u16,
    /// Where the web listener answers: the loopback, unless the config moves it.
    pub web_host: IpAddr,
}

impl TestConfig {
    pub fn new() -> Self {
        Self::with_extra("")
    }

    /// `extra` is appended to the `[server]` table, e.g. a `[server.web_tls]` table.
    pub fn with_extra(extra: &str) -> Self {
        Self::with_tables(
            Some("127.0.0.1"),
            extra,
            r#"upstream_servers = ["127.0.0.1:9"]"#,
            "enabled = false",
            "enabled = false",
        )
    }

    /// A server whose listeners bind `bind_address` as written in the file
    /// (`None` leaves the key out); `extra` is appended to `[server]` and
    /// `auth` is the body of `[auth]`.
    pub fn with_bind_address(bind_address: Option<&str>, extra: &str, auth: &str) -> Self {
        Self::with_tables(
            bind_address,
            extra,
            r#"upstream_servers = ["127.0.0.1:9"]"#,
            "enabled = false",
            auth,
        )
    }

    /// A server whose web listener binds `web_host` while DNS stays on
    /// 127.0.0.1; `extra` is appended to `[server]` as in [`Self::with_extra`].
    pub fn with_web_bind_address(web_host: IpAddr, extra: &str) -> Self {
        let mut config = Self::with_extra(&format!("web_bind_address = \"{web_host}\"\n{extra}"));
        config.web_host = web_host;
        config
    }

    /// A server that forwards to `upstream`, with blocking on, so a test can
    /// drive filtering end to end. The malware detectors are off, and so is
    /// DNSSEC: a fake upstream proves nothing, and an unvalidated answer is
    /// never cached.
    pub fn filtering(upstream: SocketAddr) -> Self {
        Self::with_tables(
            Some("127.0.0.1"),
            "",
            &format!(
                "upstream_servers = [\"{upstream}\"]\n\
                 malware_detection_enabled = false\n\
                 dnssec_mode = \"Off\""
            ),
            "enabled = true",
            "enabled = false",
        )
    }

    /// `server_extra` is appended to `[server]`; `dns`, `blocking` and `auth`
    /// are the bodies of those tables.
    fn with_tables(
        bind_address: Option<&str>,
        server_extra: &str,
        dns: &str,
        blocking: &str,
        auth: &str,
    ) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let dns_port = free_port();
        let web_port = free_port();
        let bind_line = bind_address
            .map(|bind| format!("bind_address = \"{bind}\""))
            .unwrap_or_default();
        let config = format!(
            r#"[server]
dns_port = {dns_port}
web_port = {web_port}
{bind_line}
{server_extra}

[dns]
{dns}
mdns_enabled = false

[blocking]
{blocking}

[logging]
level = "info"

[database]
path = "{db}"

[auth]
{auth}
"#,
            db = dir.path().join("ferrous.db").display(),
        );
        let path = dir.path().join("ferrous-dns.toml");
        fs::write(&path, config).unwrap();
        Self {
            dir,
            path,
            dns_port,
            web_port,
            web_host: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }

    pub fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ferrous-dns"));
        command
            .arg("--config")
            .arg(&self.path)
            .current_dir(self.dir.path())
            .env("NO_COLOR", "1");
        command
    }

    /// Starts the server and waits until its web port accepts connections.
    pub fn start(&self) -> Server {
        let log = fs::File::create(self.dir.path().join("server.log")).unwrap();
        let mut child = self
            .command()
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap();

        let started = Instant::now();
        while TcpStream::connect((self.web_host, self.web_port)).is_err() {
            if let Some(status) = child.try_wait().unwrap() {
                panic!(
                    "server exited with {status} before serving:\n{}",
                    server_log(self.dir.path())
                );
            }
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "server did not start:\n{}",
                server_log(self.dir.path())
            );
            sleep(Duration::from_millis(100));
        }
        Server { child }
    }
}

/// Killed on drop, so a failing assertion never leaves a server behind.
pub struct Server {
    pub child: Child,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
