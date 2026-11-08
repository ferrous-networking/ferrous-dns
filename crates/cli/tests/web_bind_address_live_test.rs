//! `[server] web_bind_address` against the real binary: the dashboard and the
//! API move to their own address, over HTTP and HTTPS, while DNS stays on
//! `bind_address`. 127.0.0.2 reaches the loopback without setup only on Linux.
#![cfg(target_os = "linux")]

mod server_process;

use server_process::TestConfig;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::thread::sleep;
use std::time::{Duration, Instant};

const WEB_HOST: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
const DNS_HOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// The status code of a plain HTTP/1.1 GET.
fn http_status(addr: SocketAddr, path: &str) -> u16 {
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

fn is_refused(addr: SocketAddr) -> bool {
    matches!(TcpStream::connect(addr), Err(e) if e.kind() == ErrorKind::ConnectionRefused)
}

/// The DNS listener may come up just after the web one.
fn accepts_within(addr: SocketAddr, limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    while TcpStream::connect(addr).is_err() {
        if Instant::now() > deadline {
            return false;
        }
        sleep(Duration::from_millis(50));
    }
    true
}

fn assert_dns_stays_on_bind_address(config: &TestConfig) {
    let dns = SocketAddr::new(DNS_HOST, config.dns_port);
    assert!(
        accepts_within(dns, Duration::from_secs(10)),
        "DNS over TCP on {dns}"
    );
    assert!(
        is_refused(SocketAddr::new(WEB_HOST, config.dns_port)),
        "DNS must not follow web_bind_address"
    );
    assert!(
        is_refused(SocketAddr::new(DNS_HOST, config.web_port)),
        "the web server must leave bind_address"
    );
}

#[test]
fn test_the_web_server_listens_on_web_bind_address_while_dns_keeps_bind_address() {
    let config = TestConfig::with_web_bind_address(WEB_HOST, "");
    let _server = config.start();

    let health = SocketAddr::new(WEB_HOST, config.web_port);
    assert_eq!(http_status(health, "/ferrous/api/v1/health"), 200);
    assert_dns_stays_on_bind_address(&config);
}

#[test]
fn test_https_listens_on_web_bind_address() {
    let cert_dir = tempfile::tempdir().unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key_pair)
        .unwrap();
    let cert_path = cert_dir.path().join("cert.pem");
    let key_path = cert_dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
    let config = TestConfig::with_web_bind_address(
        WEB_HOST,
        &format!(
            "\n[server.web_tls]\nenabled = true\ntls_cert_path = \"{}\"\ntls_key_path = \"{}\"",
            cert_path.display(),
            key_path.display()
        ),
    );
    let _server = config.start();

    // Plain HTTP reaches the TLS port only as a redirect, so a 301 is the TLS listener.
    let web = SocketAddr::new(WEB_HOST, config.web_port);
    assert_eq!(http_status(web, "/ferrous/api/v1/health"), 301);
    assert_dns_stays_on_bind_address(&config);
}
