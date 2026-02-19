use crate::dns::forwarding::RecordTypeMapper;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::DomainError;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RData, Record};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, warn};

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
            header.set_recursion_available(true);
            let response = builder.build(header, &[], &[] as &[Record], &[], &[]);
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

async fn send_error_response<R: ResponseHandler>(
    request: &Request,
    response_handle: &mut R,
    code: ResponseCode,
) -> ResponseInfo {
    debug!(code = ?code, "Sending error response");
    let builder = MessageResponseBuilder::from_message_request(request);
    let mut header = *request.header();
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
