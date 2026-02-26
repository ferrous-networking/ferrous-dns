use crate::dns::events::{QueryEvent, QueryEventEmitter};
use crate::dns::forwarding::{DnsResponse, MessageBuilder, ResponseParser};
use crate::dns::transport;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

pub struct QueryAttemptResult {
    pub response: DnsResponse,
    pub server_addr: SocketAddr,
    pub latency_ms: u64,
}

pub async fn query_server(
    protocol: &DnsProtocol,
    domain: &str,
    record_type: &RecordType,
    timeout_ms: u64,
    dnssec_ok: bool,
    emitter: &QueryEventEmitter,
) -> Result<QueryAttemptResult, DomainError> {
    let start = Instant::now();
    let timeout_duration = Duration::from_millis(timeout_ms);

    let query_bytes = MessageBuilder::build_query(domain, record_type, dnssec_ok)?;

    let dns_transport = transport::create_transport(protocol)?;

    let transport_response = dns_transport.send(&query_bytes, timeout_duration).await?;

    let dns_response = ResponseParser::parse(&transport_response.bytes)?;

    let response_time_us = start.elapsed().as_micros() as u64;
    let domain_arc: Arc<str> = Arc::from(domain);
    let server_str = protocol.to_string();
    emitter.emit(QueryEvent {
        domain: Arc::clone(&domain_arc),
        record_type: *record_type,
        upstream_server: server_str,
        response_time_us,
        success: !dns_response.addresses.is_empty() || !dns_response.cname_chain.is_empty(),
    });

    if dns_response.truncated {
        if let DnsProtocol::Udp { addr } = protocol {
            debug!(
                server = %addr,
                "Response truncated (TC bit), retrying via TCP"
            );

            let tcp_protocol = DnsProtocol::Tcp { addr: addr.clone() };
            let tcp_transport = transport::create_transport(&tcp_protocol)?;

            let remaining = timeout_duration
                .checked_sub(start.elapsed())
                .unwrap_or(Duration::from_millis(500));

            let tcp_start = Instant::now();
            let tcp_response = tcp_transport.send(&query_bytes, remaining).await?;
            let tcp_dns_response = ResponseParser::parse(&tcp_response.bytes)?;

            let tcp_response_time_us = tcp_start.elapsed().as_micros() as u64;
            emitter.emit(QueryEvent {
                domain: domain_arc,
                record_type: *record_type,
                upstream_server: tcp_protocol.to_string(),
                response_time_us: tcp_response_time_us,
                success: !tcp_dns_response.addresses.is_empty()
                    || !tcp_dns_response.cname_chain.is_empty(),
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
