use crate::dns::events::{QueryEvent, QueryEventEmitter};
use crate::dns::forwarding::{DnsResponse, ResponseParser};
use crate::dns::transport;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

pub struct QueryAttemptResult {
    pub response: DnsResponse,
    pub server_addr: SocketAddr,
    pub latency_ms: u64,
    pub server_display: Arc<str>,
}

fn get_display(protocol: &DnsProtocol, cache: &HashMap<Arc<DnsProtocol>, Arc<str>>) -> Arc<str> {
    cache
        .get(protocol)
        .map(Arc::clone)
        .unwrap_or_else(|| Arc::from(protocol.to_string()))
}

#[allow(clippy::too_many_arguments)]
pub async fn query_server(
    protocol: &DnsProtocol,
    query_bytes: &[u8],
    domain: &Arc<str>,
    record_type: &RecordType,
    timeout_ms: u64,
    emitter: &QueryEventEmitter,
    pool_name: &Arc<str>,
    server_displays: &Arc<HashMap<Arc<DnsProtocol>, Arc<str>>>,
) -> Result<QueryAttemptResult, DomainError> {
    let start = Instant::now();
    let timeout_duration = Duration::from_millis(timeout_ms);

    let dns_transport = transport::get_or_create_transport(protocol)?;

    let transport_response = dns_transport.send(query_bytes, timeout_duration).await?;

    let dns_response = ResponseParser::parse_bytes(transport_response.bytes)?;

    let response_time_us = start.elapsed().as_micros() as u64;
    let server_arc = get_display(protocol, server_displays);
    if emitter.is_enabled() {
        emitter.emit(QueryEvent {
            domain: Arc::clone(domain),
            record_type: *record_type,
            upstream_server: Arc::clone(&server_arc),
            response_time_us,
            success: !dns_response.addresses.is_empty() || !dns_response.cname_chain.is_empty(),
            pool_name: Some(Arc::clone(pool_name)),
        });
    }

    if dns_response.truncated {
        if let DnsProtocol::Udp { addr } = protocol {
            debug!(
                server = %addr,
                "Response truncated (TC bit), retrying via TCP"
            );

            let tcp_protocol = DnsProtocol::Tcp { addr: addr.clone() };
            let tcp_transport = transport::get_or_create_transport(&tcp_protocol)?;

            let remaining = timeout_duration
                .checked_sub(start.elapsed())
                .unwrap_or(Duration::from_millis(500));

            let tcp_start = Instant::now();
            let tcp_response = tcp_transport.send(query_bytes, remaining).await?;
            let tcp_dns_response = ResponseParser::parse_bytes(tcp_response.bytes)?;

            let tcp_response_time_us = tcp_start.elapsed().as_micros() as u64;
            let tcp_server_arc = get_display(&tcp_protocol, server_displays);
            if emitter.is_enabled() {
                emitter.emit(QueryEvent {
                    domain: Arc::clone(domain),
                    record_type: *record_type,
                    upstream_server: Arc::clone(&tcp_server_arc),
                    response_time_us: tcp_response_time_us,
                    success: !tcp_dns_response.addresses.is_empty()
                        || !tcp_dns_response.cname_chain.is_empty(),
                    pool_name: Some(Arc::clone(pool_name)),
                });
            }

            let latency_ms = start.elapsed().as_millis() as u64;
            let server_addr = protocol
                .socket_addr()
                .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

            return Ok(QueryAttemptResult {
                response: tcp_dns_response,
                server_addr,
                latency_ms,
                server_display: tcp_server_arc,
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
        server_display: server_arc,
    })
}
