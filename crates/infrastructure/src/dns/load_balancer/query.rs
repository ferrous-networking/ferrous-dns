use crate::dns::events::{QueryEvent, QueryEventEmitter};
use crate::dns::forwarding::{DnsResponse, MessageBuilder, ResponseParser};
use crate::dns::transport;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use std::net::SocketAddr;
use std::sync::Arc;
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
///
/// ## Phase 5: Query Event Logging
///
/// This function now emits a `QueryEvent` for every DNS query made to upstream
/// servers. This enables comprehensive logging of ALL queries, including:
/// - DNSSEC validation queries (DS, DNSKEY, RRSIG)
/// - TCP fallback retries
/// - Internal recursive queries
///
/// The event emission is non-blocking (100-200ns overhead) and fire-and-forget.
///
/// ## Arguments
///
/// - `protocol`: DNS protocol (UDP/TCP/DoT/DoH)
/// - `domain`: Domain to query
/// - `record_type`: DNS record type (A, AAAA, DS, DNSKEY, etc.)
/// - `timeout_ms`: Query timeout in milliseconds
/// - `emitter`: Event emitter for query logging
///
/// ## Example
///
/// ```rust,no_run
/// use ferrous_dns_infrastructure::dns::load_balancer::query::query_server;
/// use ferrous_dns_infrastructure::dns::events::QueryEventEmitter;
/// use ferrous_dns_domain::{DnsProtocol, RecordType};
/// use std::net::SocketAddr;
///
/// # async fn example() {
/// let protocol = DnsProtocol::Udp {
///     addr: "8.8.8.8:53".parse().unwrap(),
/// };
/// let (emitter, _rx) = QueryEventEmitter::new_enabled();
///
/// let result = query_server(
///     &protocol,
///     "google.com",
///     &RecordType::A,
///     5000,
///     &emitter,
/// ).await.unwrap();
/// # }
/// ```
pub async fn query_server(
    protocol: &DnsProtocol,
    domain: &str,
    record_type: &RecordType,
    timeout_ms: u64,
    emitter: &QueryEventEmitter,
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

    // PHASE 5: Emit query event for logging (100-200ns, non-blocking)
    let response_time_us = start.elapsed().as_micros() as u64;
    emitter.emit(QueryEvent {
        domain: Arc::from(domain),
        record_type: *record_type,
        upstream_server: protocol
            .socket_addr()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        response_time_us,
        success: !dns_response.addresses.is_empty() || dns_response.cname.is_some(),
    });

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

            let tcp_start = Instant::now();
            let tcp_response = tcp_transport.send(&query_bytes, remaining).await?;
            let tcp_dns_response = ResponseParser::parse(&tcp_response.bytes)?;

            // PHASE 5: Emit event for TCP retry as well
            let tcp_response_time_us = tcp_start.elapsed().as_micros() as u64;
            emitter.emit(QueryEvent {
                domain: Arc::from(domain),
                record_type: *record_type,
                upstream_server: tcp_protocol
                    .socket_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                response_time_us: tcp_response_time_us,
                success: !tcp_dns_response.addresses.is_empty() || tcp_dns_response.cname.is_some(),
            });

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
