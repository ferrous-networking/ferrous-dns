use super::message_builder::{HardeningOpts, MessageBuilder};
use super::response_parser::{DnsResponse, ResponseParser};
use super::response_validator::ResponseValidator;
use crate::dns::transport;
use ferrous_dns_domain::{DnsProtocol, DomainError, RecordType, UpstreamAddr};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

/// Queries `local_dns_server` — the LAN router — for local names and private
/// PTRs. Its answers are relayed to clients as raw wire bytes, so it gets the
/// same anti-spoofing as the upstream pools: a hardened query, the shared UDP
/// transport (which skips datagrams from another source or with another
/// transaction ID), response validation, and a TCP retry on truncation.
pub struct DnsForwarder {
    hardening: HardeningOpts,
}

impl Default for DnsForwarder {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsForwarder {
    /// DNS Cookies on, 0x20 off — the upstream pools' default.
    pub fn new() -> Self {
        Self {
            hardening: HardeningOpts {
                cookie: true,
                qname_0x20: false,
            },
        }
    }

    /// Applies the upstream pools' hardening, so `qname_case_randomization`
    /// covers the local server too.
    pub fn with_hardening(mut self, hardening: HardeningOpts) -> Self {
        self.hardening = hardening;
        self
    }

    pub async fn query(
        &self,
        server: &str,
        domain: &str,
        record_type: &RecordType,
        timeout_ms: u64,
    ) -> Result<DnsResponse, DomainError> {
        let server_addr: SocketAddr = server
            .parse()
            .map_err(|e| DomainError::IoError(format!("Invalid server address: {}", e)))?;
        let (query_bytes, validator) =
            MessageBuilder::build_query_hardened(domain, record_type, false, self.hardening)?;
        let timeout = Duration::from_millis(timeout_ms);
        let start = Instant::now();

        let udp = DnsProtocol::Udp {
            addr: UpstreamAddr::Resolved(server_addr),
        };
        let response = exchange(&udp, &query_bytes, &validator, timeout).await?;
        if !response.truncated {
            return Ok(response);
        }

        let tcp = DnsProtocol::Tcp {
            addr: UpstreamAddr::Resolved(server_addr),
        };
        let remaining = timeout
            .checked_sub(start.elapsed())
            .unwrap_or(Duration::from_millis(500));
        exchange(&tcp, &query_bytes, &validator, remaining).await
    }
}

/// One validated round trip over `protocol`, with our 0x20 case stripped from
/// the answer before anything downstream sees it.
async fn exchange(
    protocol: &DnsProtocol,
    query_bytes: &[u8],
    validator: &ResponseValidator,
    timeout: Duration,
) -> Result<DnsResponse, DomainError> {
    let reply = transport::get_or_create_transport(protocol)?
        .send(query_bytes, timeout)
        .await?;
    let mut response = ResponseParser::parse_bytes(reply.bytes)?;
    validator.validate(&response, protocol)?;
    validator.canonicalize(&mut response);
    Ok(response)
}
