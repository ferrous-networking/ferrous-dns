//! `docker stop` sends SIGTERM and waits 10 s before SIGKILL. The server must close
//! the database on that signal: SQLite checkpoints and deletes the WAL when its last
//! connection closes, and a WAL left behind has to be recovered in full at the next
//! start.
#![cfg(unix)]

use std::fs;
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

/// A loopback port free for TCP and UDP alike, since DNS listens on both.
fn free_port() -> u16 {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = tcp.local_addr().unwrap().port();
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}

fn wait_for_exit(child: &mut Child, limit: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().unwrap() {
            return Some(status);
        }
        sleep(Duration::from_millis(50));
    }
    None
}

fn server_log(dir: &Path) -> String {
    fs::read_to_string(dir.join("server.log")).unwrap_or_default()
}

#[test]
fn test_sigterm_closes_the_database_and_removes_the_wal() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("ferrous.db");
    let web_port = free_port();
    let config = format!(
        r#"[server]
dns_port = {dns_port}
web_port = {web_port}
bind_address = "127.0.0.1"

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
        dns_port = free_port(),
        db = db_path.display(),
    );
    let config_path = dir.path().join("ferrous-dns.toml");
    fs::write(&config_path, config).unwrap();

    let log = fs::File::create(dir.path().join("server.log")).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_ferrous-dns"))
        .arg("--config")
        .arg(&config_path)
        .current_dir(dir.path())
        .env("NO_COLOR", "1")
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();

    let started = Instant::now();
    while TcpStream::connect(("127.0.0.1", web_port)).is_err() {
        if let Some(status) = child.try_wait().unwrap() {
            panic!(
                "server exited with {status} before serving:\n{}",
                server_log(dir.path())
            );
        }
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "server did not start:\n{}",
            server_log(dir.path())
        );
        sleep(Duration::from_millis(100));
    }

    // SAFETY: plain kill(2) on the child this test spawned and still owns.
    assert_eq!(
        unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );

    let Some(status) = wait_for_exit(&mut child, Duration::from_secs(10)) else {
        child.kill().unwrap();
        panic!(
            "server still running 10 s after SIGTERM:\n{}",
            server_log(dir.path())
        );
    };
    assert!(
        status.success(),
        "server ended with {status} on SIGTERM:\n{}",
        server_log(dir.path())
    );

    let mut wal = db_path.into_os_string();
    wal.push("-wal");
    assert!(
        !Path::new(&wal).exists(),
        "the WAL survived a SIGTERM shutdown:\n{}",
        server_log(dir.path())
    );
}
