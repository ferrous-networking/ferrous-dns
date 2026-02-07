use crate::dns::forwarding::RecordTypeMapper;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RData, Record};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

pub struct DnsServerHandler {
    use_case: Arc<HandleDnsQueryUseCase>,
}

impl DnsServerHandler {
    pub fn new(use_case: Arc<HandleDnsQueryUseCase>) -> Self {
        Self { use_case }
    }

    fn normalize_domain(domain: &str) -> String {
        domain.trim_end_matches('.').to_string()
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
        let domain = Self::normalize_domain(&query.name().to_utf8());
        let hickory_record_type = query.query_type();
        let client_ip = request.src().ip();

        info!(domain = %domain, record_type = ?hickory_record_type, client = %client_ip, "DNS query received");

        // Centralized type conversion
        let our_record_type = match RecordTypeMapper::from_hickory(hickory_record_type) {
            Some(rt) => rt,
            None => {
                warn!(record_type = ?hickory_record_type, "Unsupported record type");
                return send_error_response(request, &mut response_handle, ResponseCode::NotImp)
                    .await;
            }
        };

        let dns_request =
            ferrous_dns_domain::DnsRequest::new(domain.clone(), our_record_type, client_ip);

        let addresses = match self.use_case.execute(&dns_request).await {
            Ok(addrs) => addrs,
            Err(e) => {
                if e.to_string().contains("blocked") {
                    warn!(domain = %domain, "Domain blocked");
                    return send_error_response(
                        request,
                        &mut response_handle,
                        ResponseCode::Refused,
                    )
                    .await;
                } else {
                    error!(error = %e, "Query resolution failed");
                    return send_error_response(
                        request,
                        &mut response_handle,
                        ResponseCode::ServFail,
                    )
                    .await;
                }
            }
        };

        // NODATA response
        if addresses.is_empty() {
            debug!(domain = %domain, "No records found (NODATA)");
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

        // Build answer records
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut answers = Vec::new();

        for addr in &addresses {
            let rdata = match addr {
                IpAddr::V4(ipv4) => RData::A(hickory_proto::rr::rdata::A(*ipv4)),
                IpAddr::V6(ipv6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(*ipv6)),
            };
            answers.push(Record::from_rdata(
                Name::from_str(&domain).unwrap_or_else(|_| Name::root()),
                60,
                rdata,
            ));
        }

        debug!(domain = %domain, answers = addresses.len(), "Sending response");

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
