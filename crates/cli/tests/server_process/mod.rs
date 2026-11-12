//! Helpers for tests that run the real `ferrous-dns` binary.
//!
//! This module is compiled into every integration-test binary that declares
//! `mod server_process;`, so items only one binary uses would otherwise trip
//! dead-code warnings under `-D warnings`.
#![allow(dead_code)]

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant};
use tempfile::TempDir;

/// What `socket(AF_INET6, …)` fails with on a kernel without IPv6, one booted
/// with `ipv6.disable=1` or built without `CONFIG_IPV6`.
#[cfg(target_os = "linux")]
pub const NO_IPV6: libc::c_int = libc::EAFNOSUPPORT;

/// Logged at startup when `"auto"` falls back to IPv4.
pub const FALLBACK_LINE: &str = "bind_address \"auto\" listens on IPv4 only";
/// Follows the address in the bind error for an explicit IPv6 address.
pub const NO_IPV6_ERROR: &str =
    "is an IPv6 address and this kernel has no IPv6: listen on an IPv4 address instead";

/// This target's `AUDIT_ARCH_*`, which libc does not export; `None` where the
/// filter below was not written for the syscall ABI.
#[cfg(target_os = "linux")]
const AUDIT_ARCH: Option<u32> = if cfg!(target_arch = "x86_64") {
    Some(0xC000_003E)
} else if cfg!(target_arch = "aarch64") {
    Some(0xC000_00B7)
} else {
    None
};

/// A seccomp program that fails `socket(AF_INET6, …)` with `errno` and allows
/// every other system call.
#[cfg(target_os = "linux")]
fn deny_af_inet6(arch: u32, errno: libc::c_int) -> [libc::sock_filter; 8] {
    use std::mem::offset_of;

    const LOAD: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
    const JUMP_IF_EQUAL: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
    const RETURN: u16 = (libc::BPF_RET | libc::BPF_K) as u16;
    let op = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    // The low half of `args[0]` sits at its start on little-endian targets.
    let domain = offset_of!(libc::seccomp_data, args) as u32;
    [
        op(LOAD, 0, 0, offset_of!(libc::seccomp_data, arch) as u32),
        op(JUMP_IF_EQUAL, 0, 4, arch),
        op(LOAD, 0, 0, offset_of!(libc::seccomp_data, nr) as u32),
        op(JUMP_IF_EQUAL, 0, 2, libc::SYS_socket as u32),
        op(LOAD, 0, 0, domain),
        op(JUMP_IF_EQUAL, 1, 0, libc::AF_INET6 as u32),
        op(RETURN, 0, 0, libc::SECCOMP_RET_ALLOW),
        op(RETURN, 0, 0, libc::SECCOMP_RET_ERRNO | errno as u32),
    ]
}

/// Installs `program` in the child `command` starts, before it execs.
#[cfg(target_os = "linux")]
fn install_seccomp(command: &mut Command, program: [libc::sock_filter; 8]) {
    use std::os::unix::process::CommandExt;

    // SAFETY: the closure runs between fork and exec, allocates nothing and
    // makes two prctl calls, which are async-signal-safe; `fprog` points into
    // `program`, which the closure owns for the length of the calls.
    unsafe {
        command.pre_exec(move || {
            let fprog = libc::sock_fprog {
                len: program.len() as libc::c_ushort,
                filter: program.as_ptr().cast_mut(),
            };
            let no_new_privs = libc::prctl(
                libc::PR_SET_NO_NEW_PRIVS,
                1 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            );
            if no_new_privs != 0
                || libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                    &raw const fprog,
                ) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

/// Prints why and returns true when `test` cannot run here: it takes IPv6
/// away from the server with a seccomp filter. Under CI that is a failure
/// instead, so the coverage is never lost silently.
#[cfg(target_os = "linux")]
pub fn skip_without_seccomp(test: &str) -> bool {
    let available = AUDIT_ARCH.is_some_and(|arch| {
        // The server binary itself, which coverage runs already follow
        // through exec; `--version` exits at once.
        let mut probe = Command::new(env!("CARGO_BIN_EXE_ferrous-dns"));
        probe.arg("--version").stdout(Stdio::null());
        install_seccomp(&mut probe, deny_af_inet6(arch, NO_IPV6));
        probe.status().is_ok_and(|status| status.success())
    });
    if available {
        return false;
    }
    assert!(
        std::env::var_os("CI").is_none(),
        "{test}: no seccomp filter can take IPv6 away on this CI runner"
    );
    eprintln!("skipping {test}: no seccomp filter can take IPv6 away here");
    true
}

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
    http_get(addr, path).0
}

/// The status code and body of a plain HTTP/1.1 GET.
pub fn http_get(addr: SocketAddr, path: &str) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    // One write: the TLS port's redirect reads a single segment, then closes.
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("not an HTTP response: {response}"));
    let body = response
        .split_once("\r\n\r\n")
        .map_or_else(String::new, |(_, body)| body.to_string());
    (status, body)
}

pub fn is_refused(addr: SocketAddr) -> bool {
    matches!(TcpStream::connect(addr), Err(e) if e.kind() == ErrorKind::ConnectionRefused)
}

/// A UDP upstream on 127.0.0.1 that sends `answer(query)` back for every
/// query, counting what it is asked by lowercase name (no trailing dot) and
/// type.
pub struct FakeUpstream {
    pub addr: SocketAddr,
    asked: Arc<Mutex<HashMap<(String, RecordType), usize>>>,
}

impl FakeUpstream {
    pub fn spawn(answer: fn(&Message) -> Message) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let asked = Arc::new(Mutex::new(HashMap::new()));
        let counts = Arc::clone(&asked);
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf) {
                let Ok(request) = Message::from_vec(&buf[..len]) else {
                    continue;
                };
                for query in &request.queries {
                    let name = query.name().to_ascii().to_ascii_lowercase();
                    let name = name.trim_end_matches('.').to_string();
                    *counts
                        .lock()
                        .unwrap()
                        .entry((name, query.query_type()))
                        .or_default() += 1;
                }
                let _ = socket.send_to(&answer(&request).to_bytes().unwrap(), peer);
            }
        });
        Self { addr, asked }
    }

    pub fn times_asked(&self, name: &str, record_type: RecordType) -> usize {
        self.asked
            .lock()
            .unwrap()
            .get(&(name.to_string(), record_type))
            .copied()
            .unwrap_or(0)
    }
}

/// Writes `cert.pem` and `key.pem` for `localhost` into `dir`, valid until
/// 2031-01-02; returns their `notAfter`.
pub fn write_certificate(dir: &Path) -> i64 {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.not_after = rcgen::date_time_ymd(2031, 1, 2);
    let cert = params.self_signed(&key_pair).unwrap();
    fs::write(dir.join("cert.pem"), cert.pem()).unwrap();
    fs::write(dir.join("key.pem"), key_pair.serialize_pem()).unwrap();
    params.not_after.unix_timestamp()
}

/// RFC 1035 §4.2.2 framing for DNS over TCP, DoT and DoQ.
pub fn framed(message: &[u8]) -> Vec<u8> {
    let mut framed = (message.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(message);
    framed
}

/// ID of the query [`private_ptr_query`] builds.
pub const PTR_QUERY_ID: u16 = 0x375;

/// A private-range PTR query, which `block_private_ptr` (on by default)
/// answers without an upstream.
pub fn private_ptr_query() -> Vec<u8> {
    let mut query = Query::new();
    query.set_name(Name::from_ascii("1.1.168.192.in-addr.arpa.").unwrap());
    query.set_query_type(RecordType::PTR);
    query.set_query_class(DNSClass::IN);
    let mut message = Message::new(PTR_QUERY_ID, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(query);
    message.to_vec().unwrap()
}

/// Whether `server` answers [`private_ptr_query`] over UDP within 5 s.
pub fn udp_answers(server: SocketAddr) -> bool {
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
        Ok((len, _)) => Message::from_vec(&buf[..len]).is_ok_and(|reply| reply.id == PTR_QUERY_ID),
        Err(_) => false,
    }
}

/// Whether `server` answers [`private_ptr_query`] over TCP within 5 s.
pub fn tcp_answers(server: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect(server) else {
        return false;
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    if stream.write_all(&framed(&private_ptr_query())).is_err() {
        return false;
    }
    let mut len = [0u8; 2];
    if stream.read_exact(&mut len).is_err() {
        return false;
    }
    let mut reply = vec![0u8; usize::from(u16::from_be_bytes(len))];
    stream.read_exact(&mut reply).is_ok()
        && Message::from_vec(&reply).is_ok_and(|reply| reply.id == PTR_QUERY_ID)
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
        Self::filtering_on("127.0.0.1", upstream)
    }

    /// [`Self::filtering`] with its listeners on `bind_address`.
    pub fn filtering_on(bind_address: &str, upstream: SocketAddr) -> Self {
        Self::with_tables(
            Some(bind_address),
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

    /// [`Self::command`] in a process where `socket(AF_INET6, …)` fails with
    /// `errno`; with [`NO_IPV6`], as on a kernel without IPv6. Guard the test
    /// with [`skip_without_seccomp`].
    #[cfg(target_os = "linux")]
    pub fn command_without_ipv6(&self, errno: libc::c_int) -> Command {
        let arch = AUDIT_ARCH.expect("guarded by skip_without_seccomp");
        let mut command = self.command();
        install_seccomp(&mut command, deny_af_inet6(arch, errno));
        command
    }

    /// Starts the server and waits until its web port accepts connections.
    pub fn start(&self) -> Server {
        self.start_with(self.command())
    }

    /// [`Self::start`] on a kernel without IPv6.
    #[cfg(target_os = "linux")]
    pub fn start_without_ipv6(&self) -> Server {
        self.start_with(self.command_without_ipv6(NO_IPV6))
    }

    /// Spawns `command` with its output in `server.log` (see [`server_log`]).
    pub fn spawn_logged(&self, mut command: Command) -> Child {
        let log = fs::File::create(self.dir.path().join("server.log")).unwrap();
        command
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap()
    }

    /// Starts `command`, built from [`Self::command`], and waits as
    /// [`Self::start`] does.
    pub fn start_with(&self, command: Command) -> Server {
        let mut child = self.spawn_logged(command);
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
