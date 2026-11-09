//! Dedicated DNS-over-HTTPS listener (RFC 8484) end-to-end test.
//!
//! The handler attributes each query to the TCP peer, so the listener must
//! hand it the connection's address; without it every request fails.

mod common;

use async_trait::async_trait;
use base64::Engine;
use common::{build_a_query, handler_with_canned_addresses, AllowAllFilter};
use ferrous_dns::server::{serve_doh, DohContext};
use ferrous_dns_application::ports::{BlockFilterEnginePort, FilterDecision};
use ferrous_dns_domain::{Config, DomainError};
use hickory_proto::op::Message;
use hickory_proto::rr::RData;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;

struct RegisteredDohIdFilter(pub &'static str);

#[async_trait]
impl BlockFilterEnginePort for RegisteredDohIdFilter {
    fn resolve_group(&self, _ip: IpAddr) -> i64 {
        0
    }
    fn resolve_group_for_request(&self, ip: IpAddr, doh_client_id: Option<&str>) -> i64 {
        if doh_client_id == Some(self.0) {
            1
        } else {
            self.resolve_group(ip)
        }
    }
    fn is_doh_id_registered(&self, client_id: &str) -> bool {
        client_id == self.0
    }
    fn check(&self, _domain: &str, _group_id: i64) -> FilterDecision {
        FilterDecision::Allow
    }
    fn explain(&self, _domain: &str, _group_id: i64) -> ferrous_dns_domain::FilterExplanation {
        unimplemented!()
    }
    fn match_candidate(
        &self,
        _domains: &[String],
        _list_lines: &[String],
        _regexes: &[String],
    ) -> Result<Vec<bool>, DomainError> {
        unimplemented!()
    }
    fn store_cname_decision(&self, _domain: &str, _group_id: i64, _ttl_secs: u64) {}
    async fn reload(&self) -> Result<(), DomainError> {
        Ok(())
    }
    async fn load_client_groups(&self) -> Result<(), DomainError> {
        Ok(())
    }
    fn compiled_domain_count(&self) -> usize {
        0
    }
    fn is_blocking_enabled(&self) -> bool {
        false
    }
    fn set_blocking_enabled(&self, _enabled: bool) {}
}

async fn send_doh_get(addr: SocketAddr, path: &str, query: &str) -> (String, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!(
                "GET {path}?dns={query} HTTP/1.1\r\nHost: {addr}\r\n\
                 Accept: application/dns-message\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();

    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("an HTTP response");
    let head = String::from_utf8_lossy(&response[..split]).into_owned();
    (head, response[split + 4..].to_vec())
}

#[tokio::test]
async fn dedicated_doh_listener_answers_a_wire_query() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let answer = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    tokio::spawn(serve_doh(
        listener,
        Arc::new(DohContext {
            handler: handler_with_canned_addresses(vec![answer], 300),
            trusted_proxies: Vec::new(),
            block_filter: Arc::new(AllowAllFilter),
            config: Arc::new(RwLock::new(Config::default())),
        }),
    ));

    let query =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(build_a_query("example.com"));
    let (head, body) = send_doh_get(addr, "/dns-query", &query).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    let message = Message::from_vec(&body).unwrap();
    let addresses: Vec<IpAddr> = message
        .answers
        .iter()
        .filter_map(|record| match &record.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            _ => None,
        })
        .collect();
    assert_eq!(addresses, [answer]);
}

#[tokio::test]
async fn doh_client_id_strict_and_permissive_validation() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let answer = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let config = Arc::new(RwLock::new(Config::default()));
    tokio::spawn(serve_doh(
        listener,
        Arc::new(DohContext {
            handler: handler_with_canned_addresses(vec![answer], 300),
            trusted_proxies: Vec::new(),
            block_filter: Arc::new(RegisteredDohIdFilter("alice-phone")),
            config: config.clone(),
        }),
    ));

    let query =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(build_a_query("example.com"));

    // 1. Invalid format is always rejected with 400 Bad Request
    let (head, body) = send_doh_get(addr, "/dns-query/Bad_ID", &query).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    assert_eq!(String::from_utf8_lossy(&body), "Invalid DoH client ID");

    // 2. Registered ID is accepted in strict mode (default)
    let (head, _) = send_doh_get(addr, "/dns-query/alice-phone", &query).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    // 3. Unregistered ID is rejected with 400 Bad Request in strict mode (default)
    let (head, body) = send_doh_get(addr, "/dns-query/unknown-device", &query).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
    assert_eq!(String::from_utf8_lossy(&body), "Unregistered DoH client ID");

    // 4. Switching to permissive mode hot-allows valid unregistered IDs
    config
        .write()
        .await
        .server
        .encrypted_dns
        .doh_allow_unregistered_ids = true;
    let (head, _) = send_doh_get(addr, "/dns-query/unknown-device", &query).await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");

    // 5. Invalid format is still rejected even in permissive mode
    let (head, _) = send_doh_get(addr, "/dns-query/-bad-", &query).await;
    assert!(head.starts_with("HTTP/1.1 400"), "{head}");
}
