//! `docker stop` sends SIGTERM and waits 10 s before SIGKILL. The server must close
//! the database on that signal: SQLite checkpoints and deletes the WAL when its last
//! connection closes, and a WAL left behind has to be recovered in full at the next
//! start.
#![cfg(unix)]

mod server_process;

use server_process::{server_log, wait_for_exit, TestConfig};
use std::time::Duration;

#[test]
fn test_sigterm_closes_the_database_and_removes_the_wal() {
    let config = TestConfig::new();
    let dir = config.dir.path();
    let mut server = config.start();

    // SAFETY: plain kill(2) on the child this test spawned and still owns.
    assert_eq!(
        unsafe { libc::kill(server.child.id() as libc::pid_t, libc::SIGTERM) },
        0
    );

    let Some(status) = wait_for_exit(&mut server.child, Duration::from_secs(10)) else {
        panic!(
            "server still running 10 s after SIGTERM:\n{}",
            server_log(dir)
        );
    };
    assert!(
        status.success(),
        "server ended with {status} on SIGTERM:\n{}",
        server_log(dir)
    );

    let wal = dir.join("ferrous.db-wal");
    assert!(
        !wal.exists(),
        "the WAL survived a SIGTERM shutdown:\n{}",
        server_log(dir)
    );
}
