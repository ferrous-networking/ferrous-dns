//! journald and `docker logs` store the server's stdout as is, so colour codes
//! written to a file or a pipe end up as literal escape bytes in every line.

mod server_process;

use server_process::{server_log, TestConfig};

#[test]
fn test_server_log_has_no_ansi_codes_when_stdout_is_not_a_terminal() {
    let config = TestConfig::new();
    let _server = config.start();

    let log = server_log(config.dir.path());
    assert!(
        log.contains("Starting Ferrous DNS Server"),
        "the server logged nothing:\n{log}"
    );
    assert!(
        !log.contains('\x1b'),
        "log lines carry ANSI escape codes:\n{log}"
    );
}
