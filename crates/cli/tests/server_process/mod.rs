//! Helpers for tests that run the real `ferrous-dns` binary.
#![allow(dead_code)]

use std::fs;
use std::net::{TcpListener, TcpStream, UdpSocket};
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

/// A config file in its own temp dir, for a server with auth off on loopback.
pub struct TestConfig {
    pub dir: TempDir,
    pub path: PathBuf,
    pub dns_port: u16,
    pub web_port: u16,
}

impl TestConfig {
    pub fn new() -> Self {
        Self::with_extra("")
    }

    /// `extra` is appended to the `[server]` table, e.g. a `[server.web_tls]` table.
    pub fn with_extra(extra: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let dns_port = free_port();
        let web_port = free_port();
        let config = format!(
            r#"[server]
dns_port = {dns_port}
web_port = {web_port}
bind_address = "127.0.0.1"
{extra}

[dns]
upstream_servers = ["127.0.0.1:9"]
mdns_enabled = false

[blocking]
enabled = false

[logging]
level = "info"

[database]
path = "{db}"

[auth]
enabled = false
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
        while TcpStream::connect(("127.0.0.1", self.web_port)).is_err() {
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
