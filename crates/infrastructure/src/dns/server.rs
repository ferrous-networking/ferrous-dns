use crate::dns::ede::{self, ExtendedDnsError};
use crate::dns::forwarding::RecordTypeMapper;
use bytes::Bytes;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::net::IpAddr;
use std::sync::Arc;
use tracing::{debug, error, warn};

const DEFAULT_TTL: u32 = 60;

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

    pub fn try_fast_path(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
    ) -> Option<(Arc<Vec<IpAddr>>, u32)> {
        self.use_case
            .try_cache_direct(domain, record_type, client_ip)
    }

    /// Returns cached wire bytes for non-IP record types (NS, CNAME, SOA, PTR,
    /// MX, TXT). The caller must patch the query ID before sending.
    pub fn try_fast_path_wire(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
    ) -> Option<(Bytes, u32)> {
        self.use_case
            .try_cache_wire_direct(domain, record_type, client_ip)
    }

    pub async fn handle_raw_udp_fallback(&self, raw: &[u8], client_ip: IpAddr) -> Option<Vec<u8>> {
        let query_msg = Message::from_vec(raw).ok()?;

        let queries: Vec<_> = query_msg.queries().to_vec();
        let query_info = queries.first()?;

        let domain_name = query_info.name().to_utf8();
        let domain = domain_name.trim_end_matches('.');
        let hickory_rt = query_info.query_type();

        let our_rt = RecordTypeMapper::from_hickory(hickory_rt)?;

        let query_id = query_msg.id();
        let rd = query_msg.recursion_desired();
        let has_edns = query_msg.extensions().is_some();
        let edns_cookie: Option<Vec<u8>> = query_msg
            .extensions()
            .as_ref()
            .and_then(|edns| extract_edns_cookie(edns.options().as_ref().iter()));
        drop(query_msg);

        let dns_request = {
            let base = ferrous_dns_domain::DnsRequest::new(domain, our_rt, client_ip);
            if let Some(c) = edns_cookie {
                base.with_cookie(c)
            } else {
                base
            }
        };

        let resolution = match self.use_case.execute(&dns_request).await {
            Ok(res) => res,
            Err(ref e @ DomainError::Blocked)
            | Err(ref e @ DomainError::DgaDomainDetected)
            | Err(ref e @ DomainError::DnsTunnelingDetected)
            | Err(ref e @ DomainError::DnsRateLimited)
            | Err(ref e @ DomainError::FilteredQuery(_)) => {
                return build_error_wire(
                    query_id,
                    rd,
                    &queries,
                    ResponseCode::Refused,
                    has_edns,
                    ede::from_domain_error(e),
                )
            }
            Err(ref e @ DomainError::DnsCookieInvalid) => {
                return build_error_wire(
                    query_id,
                    rd,
                    &queries,
                    ResponseCode::Refused,
                    has_edns,
                    ede::from_domain_error(e),
                )
            }
            Err(DomainError::DnsRateLimitedSlip) => {
                return build_truncated_wire(query_id, rd, &queries)
            }
            Err(DomainError::NxDomain) | Err(DomainError::LocalNxDomain) => {
                return build_error_wire(
                    query_id,
                    rd,
                    &queries,
                    ResponseCode::NXDomain,
                    has_edns,
                    None,
                )
            }
            Err(ref e) => {
                return build_error_wire(
                    query_id,
                    rd,
                    &queries,
                    ResponseCode::ServFail,
                    has_edns,
                    ede::from_domain_error(e),
                )
            }
        };

        let ttl = resolution.min_ttl.unwrap_or(DEFAULT_TTL);
        let addresses = &resolution.addresses;

        let mut resp = Message::new(query_id, MessageType::Response, OpCode::Query);
        resp.set_recursion_desired(rd);
        resp.set_recursion_available(true);
        for q in &queries {
            resp.add_query(q.clone());
        }

        if addresses.is_empty() {
            if let Some(ref wire_data) = resolution.upstream_wire_data {
                let has_cookie_to_inject = dns_request
                    .edns_cookie
                    .as_ref()
                    .is_some_and(|c| c.len() >= 8);

                if has_cookie_to_inject {
                    match Message::from_vec(wire_data) {
                        Ok(upstream_msg) => {
                            resp.set_response_code(upstream_msg.response_code());
                            for record in upstream_msg.answers() {
                                resp.add_answer(record.clone());
                            }
                            for record in upstream_msg.name_servers() {
                                resp.add_name_server(record.clone());
                            }
                            for record in upstream_msg.additionals() {
                                // skip existing OPT — we'll add our own with the server cookie
                                if record.record_type() != hickory_proto::rr::RecordType::OPT {
                                    resp.add_additional(record.clone());
                                }
                            }
                            // fall through to cookie injection below
                        }
                        Err(_) => {
                            // parse failed — fallback to raw bytes (no cookie)
                            let mut response = wire_data.to_vec();
                            if response.len() >= 2 {
                                response[0] = (query_id >> 8) as u8;
                                response[1] = query_id as u8;
                            }
                            return Some(response);
                        }
                    }
                } else {
                    // no cookie to inject — return raw bytes (fast path unchanged)
                    let mut response = wire_data.to_vec();
                    if response.len() >= 2 {
                        response[0] = (query_id >> 8) as u8;
                        response[1] = query_id as u8;
                    }
                    return Some(response);
                }
            }
        } else {
            let record_name = query_info.name().clone();
            for addr in addresses.iter() {
                let rdata = match *addr {
                    IpAddr::V4(ipv4) => RData::A(hickory_proto::rr::rdata::A(ipv4)),
                    IpAddr::V6(ipv6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(ipv6)),
                };
                resp.add_answer(Record::from_rdata(record_name.clone(), ttl, rdata));
            }
        }

        let mut edns_resp = hickory_proto::op::Edns::new();
        if let Some(ref cookie_data) = dns_request.edns_cookie {
            let raw = cookie_data.as_bytes();
            if raw.len() >= 8 {
                let mut client_cookie = [0u8; 8];
                client_cookie.copy_from_slice(&raw[..8]);
                let server_cookie = self
                    .use_case
                    .cookie_guard()
                    .generate_server_cookie(client_ip, &client_cookie);
                let mut opt_data = Vec::with_capacity(16);
                opt_data.extend_from_slice(&raw[..8]);
                opt_data.extend_from_slice(&server_cookie);
                edns_resp
                    .options_mut()
                    .insert(EdnsOption::Unknown(10, opt_data));
            }
        }
        resp.set_edns(edns_resp);

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
                return send_error_response(
                    request,
                    &mut response_handle,
                    ResponseCode::FormErr,
                    None,
                )
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
                return send_error_response(
                    request,
                    &mut response_handle,
                    ResponseCode::NotImp,
                    None,
                )
                .await;
            }
        };

        let edns_cookie: Option<Vec<u8>> = request
            .edns()
            .and_then(|edns| extract_edns_cookie(edns.options().as_ref().iter()));

        let dns_request = {
            let base = ferrous_dns_domain::DnsRequest::new(domain, our_record_type, client_ip);
            if let Some(c) = edns_cookie {
                base.with_cookie(c)
            } else {
                base
            }
        };
        let domain_ref = &dns_request.domain;

        let resolution = match self.use_case.execute(&dns_request).await {
            Ok(res) => res,
            Err(ref e @ DomainError::Blocked) => {
                warn!(domain = %domain_ref, "Domain blocked");
                return send_error_response(
                    request,
                    &mut response_handle,
                    ResponseCode::Refused,
                    ede::from_domain_error(e),
                )
                .await;
            }
            Err(ref e @ DomainError::DnsTunnelingDetected) => {
                debug!(domain = %domain_ref, client = %client_ip, "DNS tunneling detected");
                return send_error_response(
                    request,
                    &mut response_handle,
                    ResponseCode::Refused,
                    ede::from_domain_error(e),
                )
                .await;
            }
            Err(ref e @ DomainError::DnsRateLimited) => {
                debug!(domain = %domain_ref, client = %client_ip, "Rate limited");
                return send_error_response(
                    request,
                    &mut response_handle,
                    ResponseCode::Refused,
                    ede::from_domain_error(e),
                )
                .await;
            }
            Err(ref e @ DomainError::DgaDomainDetected) => {
                debug!(domain = %domain_ref, client = %client_ip, "DGA domain detected");
                return send_error_response(
                    request,
                    &mut response_handle,
                    ResponseCode::Refused,
                    ede::from_domain_error(e),
                )
                .await;
            }
            Err(ref e @ DomainError::FilteredQuery(ref reason)) => {
                debug!(domain = %domain_ref, reason = %reason, "Query filtered by policy");
                return send_error_response(
                    request,
                    &mut response_handle,
                    ResponseCode::Refused,
                    ede::from_domain_error(e),
                )
                .await;
            }
            Err(ref e @ DomainError::DnsCookieInvalid) => {
                debug!(domain = %domain_ref, client = %client_ip, "DNS cookie invalid");
                return send_error_response(
                    request,
                    &mut response_handle,
                    ResponseCode::Refused,
                    ede::from_domain_error(e),
                )
                .await;
            }
            Err(DomainError::DnsRateLimitedSlip) => {
                debug!(domain = %domain_ref, client = %client_ip, "Rate limited (TC=1 slip)");
                return send_truncated_response(request, &mut response_handle).await;
            }
            Err(DomainError::NxDomain) | Err(DomainError::LocalNxDomain) => {
                return send_error_response(
                    request,
                    &mut response_handle,
                    ResponseCode::NXDomain,
                    None,
                )
                .await;
            }
            Err(e) => {
                error!(error = %e, "Query resolution failed");
                return send_error_response(
                    request,
                    &mut response_handle,
                    ResponseCode::ServFail,
                    ede::from_domain_error(&e),
                )
                .await;
            }
        };

        let ttl = resolution.min_ttl.unwrap_or(DEFAULT_TTL);
        let addresses = resolution.addresses;

        if addresses.is_empty() {
            if let Some(ref wire_data) = resolution.upstream_wire_data {
                if let Ok(message) = Message::from_vec(wire_data) {
                    let answers: Vec<Record> = message.answers().to_vec();
                    let authority: Vec<Record> = message.name_servers().to_vec();
                    let additional: Vec<Record> = message.additionals().to_vec();
                    let builder = MessageResponseBuilder::from_message_request(request);
                    let mut header = *request.header();
                    header.set_message_type(MessageType::Response);
                    header.set_recursion_available(true);
                    let response = builder.build(
                        header,
                        answers.iter(),
                        authority.iter(),
                        &[],
                        additional.iter(),
                    );
                    return match response_handle.send_response(response).await {
                        Ok(info) => info,
                        Err(e) => {
                            error!(error = %e, "Failed to send wire data response");
                            ResponseInfo::from(*request.header())
                        }
                    };
                }
            }
            debug!(domain = %domain_ref, "No records found (NODATA)");
            let builder = MessageResponseBuilder::from_message_request(request);
            let mut header = *request.header();
            header.set_message_type(MessageType::Response);
            header.set_recursion_available(true);
            let response = builder.build(header, &[], &[], &[], &[]);
            return match response_handle.send_response(response).await {
                Ok(info) => info,
                Err(e) => {
                    error!(error = %e, "Failed to send NODATA response");
                    ResponseInfo::from(*request.header())
                }
            };
        }

        let record_name: hickory_proto::rr::Name = query.name().clone().into();

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

/// Extracts the raw EDNS option-10 (DNS Cookie, RFC 7873) bytes from an
/// iterator over EDNS options. Returns `None` when no cookie option is present.
fn extract_edns_cookie<'a>(
    mut options: impl Iterator<Item = &'a (hickory_proto::rr::rdata::opt::EdnsCode, EdnsOption)>,
) -> Option<Vec<u8>> {
    options.find_map(|(_, opt)| {
        if let EdnsOption::Unknown(10, data) = opt {
            Some(data.clone())
        } else {
            None
        }
    })
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
    has_edns: bool,
    ede: Option<ExtendedDnsError>,
) -> Option<Vec<u8>> {
    let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
    resp.set_recursion_desired(rd);
    resp.set_recursion_available(true);
    resp.set_response_code(code);
    for q in queries {
        resp.add_query(q.clone());
    }
    if has_edns {
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.set_version(0);
        if let Some(ede) = ede {
            let mut data = Vec::with_capacity(2);
            data.extend_from_slice(&ede.info_code.to_be_bytes());
            if let Some(text) = ede.extra_text {
                data.extend_from_slice(text.as_bytes());
            }
            edns.options_mut()
                .insert(EdnsOption::Unknown(ede::OPTION_CODE, data));
        }
        resp.set_edns(edns);
    }
    encode_message(&resp)
}

fn build_truncated_wire(
    id: u16,
    rd: bool,
    queries: &[hickory_proto::op::Query],
) -> Option<Vec<u8>> {
    let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
    resp.set_recursion_desired(rd);
    resp.set_recursion_available(true);
    resp.set_truncated(true);
    resp.set_response_code(ResponseCode::NoError);
    for q in queries {
        resp.add_query(q.clone());
    }
    encode_message(&resp)
}

async fn send_truncated_response<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
) -> ResponseInfo {
    debug!("Sending truncated (TC=1) response");
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut header = *request.header();
    header.set_message_type(MessageType::Response);
    header.set_truncated(true);
    header.set_recursion_available(true);
    let response = builder.build(header, &[], &[], &[], &[]);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            error!(error = %e, "Failed to send truncated response");
            ResponseInfo::from(*request.header())
        }
    }
}

async fn send_error_response<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    code: ResponseCode,
    ede: Option<ExtendedDnsError>,
) -> ResponseInfo {
    debug!(code = ?code, "Sending error response");
    let mut builder = MessageResponseBuilder::from_message_request(request);
    let mut header = *request.header();
    header.set_message_type(MessageType::Response);
    header.set_response_code(code);
    header.set_recursion_available(true);

    if let Some(ede) = ede {
        if request.edns().is_some() {
            let mut edns = Edns::new();
            edns.set_max_payload(4096);
            edns.set_version(0);
            let mut data = Vec::with_capacity(2);
            data.extend_from_slice(&ede.info_code.to_be_bytes());
            if let Some(text) = ede.extra_text {
                data.extend_from_slice(text.as_bytes());
            }
            edns.options_mut()
                .insert(EdnsOption::Unknown(ede::OPTION_CODE, data));
            builder.edns(edns);
        }
    }

    let response = builder.build(header, &[], &[], &[], &[]);
    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            error!(error = %e, "Failed to send error response");
            ResponseInfo::from(*request.header())
        }
    }
}
