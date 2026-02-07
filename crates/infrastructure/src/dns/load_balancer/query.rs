//! Shared query logic for all load balancing strategies
//!
//! Encapsulates the transport-level query flow:
//! 1. Build DNS message (via MessageBuilder)
//! 2. Create transport for protocol
//! 3. Send query via transport
//! 4. Parse response (via ResponseParser)
//! 5. Handle TCP fallback on truncation
//!
//! This eliminates the duplicated Resolver creation that was in
//! balanced.rs, failover.rs, and parallel.rs.

use crate::dns::forwarding::{DnsResponse, MessageBuilder, ResponseParser};
use crate::dns::transport;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::debug;

/// Result of a single-server query attempt
pub struct QueryAttemptResult {
    pub response: DnsResponse,
    pub server_addr: SocketAddr,
    pub latency_ms: u64,
}

/// Execute a DNS query against a single upstream server via the transport layer
///
/// Handles the full flow: build message → send via transport → parse response.
/// If the UDP response is truncated (TC bit), automatically retries via TCP.
pub async fn query_server(
    protocol: &DnsProtocol,
    domain: &str,
    record_type: &RecordType,
    timeout_ms: u64,
) -> Result<QueryAttemptResult, DomainError> {
    let start = Instant::now();
    let timeout_duration = Duration::from_millis(timeout_ms);

    // Build DNS query message
    let query_bytes = MessageBuilder::build_query(domain, record_type)?;

    // Create transport for this protocol (enum dispatch — no heap alloc)
    let dns_transport = transport::create_transport(protocol)?;

    // Send query and receive response
    let transport_response = dns_transport.send(&query_bytes, timeout_duration).await?;

    // Parse the raw response
    let dns_response = ResponseParser::parse(&transport_response.bytes)?;

    // Handle TCP fallback: if response is truncated and we used UDP, retry via TCP
    if dns_response.truncated {
        if let DnsProtocol::Udp { addr } = protocol {
            debug!(
                server = %addr,
                "Response truncated (TC bit), retrying via TCP"
            );

            let tcp_protocol = DnsProtocol::Tcp { addr: *addr };
            let tcp_transport = transport::create_transport(&tcp_protocol)?;

            let remaining = timeout_duration
                .checked_sub(start.elapsed())
                .unwrap_or(Duration::from_millis(500));

            let tcp_response = tcp_transport.send(&query_bytes, remaining).await?;
            let tcp_dns_response = ResponseParser::parse(&tcp_response.bytes)?;

            let latency_ms = start.elapsed().as_millis() as u64;
            let server_addr = protocol
                .socket_addr()
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

            return Ok(QueryAttemptResult {
                response: tcp_dns_response,
                server_addr,
                latency_ms,
            });
        }
    }

    let latency_ms = start.elapsed().as_millis() as u64;
    let server_addr = protocol
        .socket_addr()
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

    Ok(QueryAttemptResult {
        response: dns_response,
        server_addr,
        latency_ms,
    })
}
