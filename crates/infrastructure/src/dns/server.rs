use crate::dns::forwarding::RecordTypeMapper;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::{Name, RData, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, warn};

#[derive(Clone)]
pub struct DnsServerHandler {
    use_case: Arc<HandleDnsQueryUseCase>,
}

impl DnsServerHandler {
    pub fn new(use_case: Arc<HandleDnsQueryUseCase>) -> Self {
        Self { use_case }
    }

    fn normalize_domain(domain: &str) -> &str {
        domain.trim_end_matches('.')
    }

    /// Fast-path cache probe: no block-filter, no logging, no allocation on miss.
    /// Returns `Some((addresses, ttl))` when the domain is cached with ≥1 address.
    pub fn try_fast_path(
        &self,
        domain: &str,
        record_type: RecordType,
    ) -> Option<(Arc<Vec<IpAddr>>, u32)> {
        self.use_case.try_cache_direct(domain, record_type)
    }

    /// Fallback for the custom UDP loop: parse `raw` with hickory_proto, run the
    /// full use-case pipeline (block-filter, upstream, logging), and serialize
    /// the response back to wire bytes.
    ///
    /// Returns `None` only when the packet cannot be parsed at all.
    pub async fn handle_raw_udp_fallback(&self, raw: &[u8], client_ip: IpAddr) -> Option<Vec<u8>> {
        let query_msg = Message::from_vec(raw).ok()?;

        let queries: Vec<_> = query_msg.queries().to_vec();
        let query_info = queries.first()?;

        let domain_name = query_info.name().to_utf8();
        let domain = domain_name.trim_end_matches('.');
        let hickory_rt = query_info.query_type();

        let our_rt = RecordTypeMapper::from_hickory(hickory_rt)?;
        let dns_request = ferrous_dns_domain::DnsRequest::new(domain, our_rt, client_ip);

        let query_id = query_msg.id();
        let rd = query_msg.recursion_desired();
        drop(query_msg);

        let resolution = match self.use_case.execute(&dns_request).await {
            Ok(res) => res,
            Err(DomainError::Blocked) => {
                return Some(build_error_wire(
                    query_id,
                    rd,
                    &queries,
                    ResponseCode::Refused,
                ))
            }
            Err(_) => {
                return Some(build_error_wire(
                    query_id,
                    rd,
                    &queries,
                    ResponseCode::ServFail,
                ))
            }
        };

        let ttl = resolution.min_ttl.unwrap_or(60);
        let addresses = &resolution.addresses;

        let mut resp = Message::new(query_id, MessageType::Response, OpCode::Query);
        resp.set_recursion_desired(rd);
        resp.set_recursion_available(true);
        for q in &queries {
            resp.add_query(q.clone());
        }

        if addresses.is_empty() {
            for record in resolution.authority_records {
                resp.add_name_server(record);
            }
        } else {
            let record_name = Name::from_str(domain).unwrap_or_else(|_| Name::root());
            for addr in addresses.iter() {
                let rdata = match *addr {
                    IpAddr::V4(ipv4) => RData::A(hickory_proto::rr::rdata::A(ipv4)),
                    IpAddr::V6(ipv6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(ipv6)),
                };
                resp.add_answer(Record::from_rdata(record_name.clone(), ttl, rdata));
            }
        }

        encode_message(&resp)
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsServerHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(e) => {
                error!(error = %e, "Failed to parse request info");
                return send_error_response(request, &mut response_handle, ResponseCode::FormErr)
                    .await;
            }
        };

        let query = &request_info.query;
        let raw_domain = query.name().to_utf8();
        let domain = Self::normalize_domain(&raw_domain);
        let hickory_record_type = query.query_type();
        let client_ip = request.src().ip();

        debug!(domain = %domain, record_type = ?hickory_record_type, client = %client_ip, "DNS query received");

        let our_record_type = match RecordTypeMapper::from_hickory(hickory_record_type) {
            Some(rt) => rt,
            None => {
                warn!(record_type = ?hickory_record_type, "Unsupported record type");
                return send_error_response(request, &mut response_handle, ResponseCode::NotImp)
                    .await;
            }
        };

        let dns_request = ferrous_dns_domain::DnsRequest::new(domain, our_record_type, client_ip);
        let domain_ref = &dns_request.domain;

        let resolution = match self.use_case.execute(&dns_request).await {
            Ok(res) => res,
            Err(DomainError::Blocked) => {
                warn!(domain = %domain_ref, "Domain blocked");
                return send_error_response(request, &mut response_handle, ResponseCode::Refused)
                    .await;
            }
            Err(e) => {
                error!(error = %e, "Query resolution failed");
                return send_error_response(request, &mut response_handle, ResponseCode::ServFail)
                    .await;
            }
        };

        let ttl = resolution.min_ttl.unwrap_or(60);
        let addresses = resolution.addresses;

        if addresses.is_empty() {
            debug!(domain = %domain_ref, "No records found (NODATA)");
            let builder = MessageResponseBuilder::from_message_request(request);
            let mut header = *request.header();
            header.set_message_type(MessageType::Response);
            header.set_recursion_available(true);
            let authority = resolution.authority_records;
            let response = builder.build(header, &[], authority.iter(), &[], &[]);
            return match response_handle.send_response(response).await {
                Ok(info) => info,
                Err(e) => {
                    error!(error = %e, "Failed to send NODATA response");
                    ResponseInfo::from(*request.header())
                }
            };
        }

        let record_name = Name::from_str(domain_ref).unwrap_or_else(|_| Name::root());

        let builder = MessageResponseBuilder::from_message_request(request);
        let mut answers = Vec::with_capacity(addresses.len());
        for addr in addresses.iter() {
            let rdata = match *addr {
                IpAddr::V4(ipv4) => RData::A(hickory_proto::rr::rdata::A(ipv4)),
                IpAddr::V6(ipv6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(ipv6)),
            };
            answers.push(Record::from_rdata(record_name.clone(), ttl, rdata));
        }

        debug!(domain = %domain_ref, answers = addresses.len(), "Sending response");
        let mut header = *request.header();
        header.set_message_type(MessageType::Response);
        header.set_recursion_available(true);
        let response = builder.build(header, answers.iter(), &[], &[], &[]);
        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                error!(error = %e, "Failed to send response");
                ResponseInfo::from(*request.header())
            }
        }
    }
}

fn encode_message(msg: &Message) -> Option<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut buf);
    msg.emit(&mut encoder).ok()?;
    Some(buf)
}

fn build_error_wire(
    id: u16,
    rd: bool,
    queries: &[hickory_proto::op::Query],
    code: ResponseCode,
) -> Vec<u8> {
    let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
    resp.set_recursion_desired(rd);
    resp.set_recursion_available(true);
    resp.set_response_code(code);
    for q in queries {
        resp.add_query(q.clone());
    }
    encode_message(&resp).unwrap_or_default()
}

async fn send_error_response<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    code: ResponseCode,
) -> ResponseInfo {
    debug!(code = ?code, "Sending error response");
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut header = *request.header();
    header.set_message_type(MessageType::Response);
    header.set_response_code(code);
    header.set_recursion_available(true);
    let response = builder.build(header, &[], &[], &[], &[]);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            error!(error = %e, "Failed to send error response");
            ResponseInfo::from(*request.header())
        }
    }
}
