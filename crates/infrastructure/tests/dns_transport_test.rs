use bytes::Bytes;
use ferrous_dns_domain::{DomainError, UpstreamAddr};
use ferrous_dns_infrastructure::dns::fast_path;
use ferrous_dns_infrastructure::dns::forwarding::ResponseParser;
use ferrous_dns_infrastructure::dns::transport::tcp::TcpTransport;
use ferrous_dns_infrastructure::dns::wire_response;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TCP_QUERY: [u8; 12] = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];

async fn echo_one_message(stream: &mut TcpStream) {
    let len = stream.read_u16().await.unwrap();
    let mut message = vec![0; usize::from(len)];
    stream.read_exact(&mut message).await.unwrap();
    stream.write_u16(len).await.unwrap();
    stream.write_all(&message).await.unwrap();
}

/// Echoes one length-prefixed message per connection, then closes it, the way
/// servers retire idle connections (RFC 7766 §6.2.3).
async fn spawn_one_answer_per_connection_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            echo_one_message(&mut stream).await;
        }
    });
    addr
}

/// Answers only the very first message, then keeps every connection open and silent.
async fn spawn_server_that_stalls_after_one_answer() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((mut stream, _)) = listener.accept().await {
            if held.is_empty() {
                echo_one_message(&mut stream).await;
            }
            held.push(stream);
        }
    });
    addr
}

#[tokio::test]
async fn tcp_transport_reconnects_when_the_server_closed_the_pooled_connection() {
    let addr = spawn_one_answer_per_connection_server().await;
    let transport = TcpTransport::new(UpstreamAddr::Resolved(addr));

    for attempt in 0..2 {
        let answer = transport
            .send(&TCP_QUERY, Duration::from_secs(2))
            .await
            .unwrap_or_else(|e| panic!("attempt {attempt}: {e}"));
        assert_eq!(answer.as_ref(), &TCP_QUERY);
    }
}

#[tokio::test]
async fn tcp_transport_reconnect_stays_within_the_query_timeout() {
    let addr = spawn_server_that_stalls_after_one_answer().await;
    let transport = TcpTransport::new(UpstreamAddr::Resolved(addr));
    transport
        .send(&TCP_QUERY, Duration::from_secs(2))
        .await
        .unwrap();

    let timeout = Duration::from_millis(400);
    let started = Instant::now();
    assert!(transport.send(&TCP_QUERY, timeout).await.is_err());
    let elapsed = started.elapsed();
    assert!(
        elapsed < timeout + timeout / 2,
        "a stalled pooled connection plus the reconnect took {elapsed:?}"
    );
}

fn build_edns_query() -> Vec<u8> {
    vec![
        0x00, 0x01, // ID
        0x00, 0x00, // FLAGS (plain query, no flags)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x01, // ARCOUNT = 1 (one OPT record)
        // QNAME: google.com.
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        // QTYPE A, QCLASS IN
        0x00, 0x01, 0x00, 0x01, // OPT RR
        0x00, // NAME = root
        0x00, 0x29, // TYPE = OPT (41)
        0x10, 0x00, // CLASS = 4096 (client UDP payload size)
        0x00, 0x00, 0x00, 0x00, // TTL: extended RCODE=0, version=0, DO=0, Z=0
        0x00, 0x00, // RDLENGTH = 0
    ]
}

/// Models a real `dig +dnssec` query: EDNS OPT with the DO bit set and a
/// COOKIE option in the RDATA (as dig 9.18+ sends).
fn build_edns_do_query() -> Vec<u8> {
    vec![
        0x00, 0x01, // ID
        0x01, 0x20, // FLAGS: RD + AD
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x01, // ARCOUNT = 1 (one OPT record)
        // QNAME: google.com.
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        // QTYPE A, QCLASS IN
        0x00, 0x01, 0x00, 0x01, // OPT RR
        0x00, // NAME = root
        0x00, 0x29, // TYPE = OPT (41)
        0x04, 0xd0, // CLASS = 1232 (client UDP payload size)
        0x00, 0x00, 0x80, 0x00, // TTL: ext RCODE=0, version=0, DO=1, Z=0
        0x00, 0x0c, // RDLENGTH = 12
        0x00, 0x0a, // OPTION-CODE = COOKIE (10)
        0x00, 0x08, // OPTION-LENGTH = 8
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // 8-byte client cookie
    ]
}

#[test]
fn test_fast_path_detects_do_bit() {
    let with_do = fast_path::parse_query(&build_edns_do_query())
        .expect("EDNS+DO query should be fast-path parseable");
    assert!(
        with_do.wants_dnssec,
        "wants_dnssec must be true when the client set the EDNS DO bit"
    );

    let without_do = fast_path::parse_query(&build_edns_query())
        .expect("EDNS query should be fast-path parseable");
    assert!(
        !without_do.wants_dnssec,
        "wants_dnssec must be false when the DO bit is clear"
    );
}

#[test]
fn test_fast_path_response_includes_opt_when_client_sent_edns() {
    let query_bytes = build_edns_query();

    let fast_query = fast_path::parse_query(&query_bytes)
        .expect("Minimal EDNS query should be fast-path parseable");

    assert!(
        fast_query.has_edns(),
        "FastPathQuery.has_edns must be true when query contains OPT record"
    );

    let addresses: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];

    let mut wire = [0u8; wire_response::RESPONSE_BUF_LEN];
    let wire_len = wire_response::build_cache_hit_response(
        &fast_query,
        &query_bytes,
        &addresses,
        300,
        None,
        &mut wire,
    )
    .expect("build_cache_hit_response should succeed");

    let arcount = u16::from_be_bytes([wire[10], wire[11]]);
    assert_eq!(
        arcount, 1,
        "ARCOUNT must be 1 when OPT record is included (RFC 6891 §6.1.1)"
    );

    let opt_start = wire_len - 11;
    assert_eq!(wire[opt_start], 0x00, "OPT NAME must be root (0x00)");
    assert_eq!(
        u16::from_be_bytes([wire[opt_start + 1], wire[opt_start + 2]]),
        41,
        "OPT TYPE must be 41"
    );
}

#[test]
fn unparsable_upstream_answer_is_an_invalid_response() {
    let error = ResponseParser::parse_bytes(Bytes::from_static(&[0xde, 0xad])).unwrap_err();
    assert!(
        matches!(error, DomainError::InvalidDnsResponse(_)),
        "{error:?}"
    );
}

// Transport errors determine which failures can trigger upstream failover.

#[test]
fn test_transport_error_classification_typed_variants() {
    assert!(ResponseParser::is_transport_error(
        &DomainError::TransportTimeout {
            server: "8.8.8.8:53".into()
        }
    ));
    assert!(ResponseParser::is_transport_error(
        &DomainError::TransportConnectionRefused {
            server: "1.1.1.1:53".into()
        }
    ));
    assert!(ResponseParser::is_transport_error(
        &DomainError::TransportConnectionReset {
            server: "9.9.9.9:53".into()
        }
    ));
    assert!(ResponseParser::is_transport_error(
        &DomainError::TransportNoHealthyServers
    ));
    assert!(ResponseParser::is_transport_error(
        &DomainError::TransportAllServersUnreachable
    ));
    assert!(ResponseParser::is_transport_error(
        &DomainError::SpoofedResponse {
            server: "8.8.8.8:53".into(),
            reason: "cookie mismatch".into()
        }
    ));

    assert!(!ResponseParser::is_transport_error(&DomainError::NxDomain));
    assert!(!ResponseParser::is_transport_error(&DomainError::Blocked));
}

#[test]
fn test_fast_path_response_no_opt_when_client_has_no_edns() {
    let mut query_bytes: Vec<u8> = vec![
        0x00, 0x01, // ID
        0x00, 0x00, // FLAGS (standard query)
        0x00, 0x01, // QDCOUNT = 1
        0x00, 0x00, // ANCOUNT = 0
        0x00, 0x00, // NSCOUNT = 0
        0x00, 0x00, // ARCOUNT = 0 (no OPT)
        // QNAME: google.com.
        0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00,
        // QTYPE A, QCLASS IN
        0x00, 0x01, 0x00, 0x01,
    ];
    query_bytes.resize(query_bytes.len(), 0);

    let fast_query =
        fast_path::parse_query(&query_bytes).expect("Minimal query should be fast-path parseable");

    assert!(
        !fast_query.has_edns(),
        "FastPathQuery.has_edns must be false when no OPT record is present"
    );

    let addresses: Vec<IpAddr> = vec!["1.2.3.4".parse().unwrap()];
    let mut wire = [0u8; wire_response::RESPONSE_BUF_LEN];
    let _wire_len = wire_response::build_cache_hit_response(
        &fast_query,
        &query_bytes,
        &addresses,
        300,
        None,
        &mut wire,
    )
    .expect("build_cache_hit_response should succeed");

    let arcount = u16::from_be_bytes([wire[10], wire[11]]);
    assert_eq!(arcount, 0, "ARCOUNT must be 0 when client did not send OPT");
}
