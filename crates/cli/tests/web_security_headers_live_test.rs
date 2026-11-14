//! Every response of the web listener tells the browser not to frame the
//! dashboard from another site, not to guess content types and not to send
//! the dashboard's URLs to other sites; checked against the real binary.

mod server_process;

use server_process::TestConfig;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::time::Duration;

const SECURITY_HEADERS: [(&str, &str); 4] = [
    ("content-security-policy", "frame-ancestors 'self'"),
    ("x-frame-options", "SAMEORIGIN"),
    ("x-content-type-options", "nosniff"),
    ("referrer-policy", "same-origin"),
];

/// Status line and headers of a GET, lowercased names, as sent.
fn head(addr: SocketAddr, path: &str) -> (u16, Vec<(String, String)>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let text = String::from_utf8_lossy(&response);
    let (head, _) = text
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("not an HTTP response for {path}"));
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split(' ').nth(1))
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("no status line for {path}"));
    let headers = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_ascii_lowercase(), value.trim().to_string()))
        .collect();
    (status, headers)
}

fn values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
        .collect()
}

#[test]
fn test_every_kind_of_response_carries_the_security_headers() {
    let config = TestConfig::with_extra(
        "pihole_compat = true\nmetrics_enabled = true\n\n[server.encrypted_dns]\ndoh_enabled = true",
    );
    let _server = config.start();
    let web = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.web_port);

    for (path, expected) in [
        ("/login.html", 200),
        ("/static/shared.js", 200),
        ("/static/vendor/alpinejs-3.13.5.min.js", 200),
        ("/ferrous-config.js", 200),
        ("/ferrous/api/v1/health", 200),
        ("/ferrous/api/v1/docs", 200),
        ("/ferrous/api/v1/openapi.json", 200),
        ("/api/info/login", 200),
        ("/metrics", 200),
        ("/dns-query", 400),
        ("/no-such-page", 404),
    ] {
        let (status, headers) = head(web, path);
        assert_eq!(status, expected, "{path}");
        for (name, value) in SECURITY_HEADERS {
            assert_eq!(values(&headers, name), [value], "{path}: {name}");
        }
    }
}

/// nosniff makes a browser refuse a script or stylesheet whose type is not
/// one; every embedded asset must keep naming its own.
#[test]
fn test_scripts_and_stylesheets_keep_their_content_types() {
    let config = TestConfig::new();
    let _server = config.start();
    let web = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), config.web_port);

    for (path, kind) in [
        ("/static/shared.js", "application/javascript"),
        ("/static/shared.css", "text/css"),
        (
            "/static/vendor/alpinejs-3.13.5.min.js",
            "application/javascript",
        ),
        ("/static/vendor/tailwind-preflight-3.4.17.css", "text/css"),
        ("/ferrous-config.js", "application/javascript"),
    ] {
        let (_, headers) = head(web, path);
        let content_type = values(&headers, "content-type");
        assert!(
            content_type.iter().any(|value| value.starts_with(kind)),
            "{path}: {content_type:?}"
        );
    }
}
