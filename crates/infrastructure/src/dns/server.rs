use ferrous_dns_application::use_cases::handle_dns_query::HandleDnsQueryUseCase;
use ferrous_dns_domain::{DnsRequest, RecordType};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RData, Record, RecordType as HickoryRecordType};
use hickory_server::authority::MessageResponseBuilder;
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

/// DNS Server Handler that processes incoming DNS requests
pub struct DnsServerHandler {
    use_case: Arc<HandleDnsQueryUseCase>,
}

impl DnsServerHandler {
    pub fn new(use_case: Arc<HandleDnsQueryUseCase>) -> Self {
        Self { use_case }
    }
}

#[async_trait::async_trait]
impl RequestHandler for DnsServerHandler {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        // Extract query info from request
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(e) => {
                error!(error = %e, "Failed to parse request info");
                return send_error_response(request, &mut response_handle, ResponseCode::FormErr).await;
            }
        };

        let query = &request_info.query;
        let domain = query.name().to_utf8();
        let record_type = query.query_type();
        let client_ip = request.src().ip();

        info!(
            domain = %domain,
            record_type = ?record_type,
            client = %client_ip,
            "DNS query received"
        );

        // Convert Hickory record type to our domain type
        let our_record_type = match record_type {
            HickoryRecordType::A => RecordType::A,
            HickoryRecordType::AAAA => RecordType::AAAA,
            HickoryRecordType::MX => RecordType::MX,
            HickoryRecordType::TXT => RecordType::TXT,
            _ => {
                warn!(record_type = ?record_type, "Unsupported record type");
                return send_error_response(request, &mut response_handle, ResponseCode::NotImp).await;
            }
        };

        // Create DNS request
        let dns_request = DnsRequest::new(domain.clone(), our_record_type, client_ip);

        // Handle query via use case
        let addresses = match self.use_case.execute(&dns_request).await {
            Ok(addrs) => addrs,
            Err(e) => {
                if e.to_string().contains("blocked") {
                    warn!(domain = %domain, "Domain blocked");
                    return send_error_response(request, &mut response_handle, ResponseCode::Refused).await;
                } else {
                    error!(error = %e, "Query resolution failed");
                    return send_error_response(request, &mut response_handle, ResponseCode::ServFail).await;
                }
            }
        };

        // Build response using MessageResponseBuilder
        let builder = MessageResponseBuilder::from_message_request(request);
        let mut answers = Vec::new();

        // Create answer records
        for addr in &addresses {
            let rdata = match addr {
                IpAddr::V4(ipv4) => RData::A(hickory_proto::rr::rdata::A(*ipv4)),
                IpAddr::V6(ipv6) => RData::AAAA(hickory_proto::rr::rdata::AAAA(*ipv6)),
            };

            let record = Record::from_rdata(
                Name::from_str(&domain).unwrap_or_else(|_| Name::root()),
                60, // TTL
                rdata,
            );

            answers.push(record);
        }

        debug!(domain = %domain, answers = addresses.len(), "Sending response");

        // Build and send response
        let response = builder.build(
            request.header().clone(),
            answers.iter(),
            &[],
            &[],
            &[],
        );

        match response_handle.send_response(response).await {
            Ok(info) => info,
            Err(e) => {
                error!(error = %e, "Failed to send response");
                ResponseInfo::from(request.header().clone())
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
    let mut header = request.header().clone();
    header.set_response_code(code);

    let response = builder.build(header, &[], &[], &[], &[]);

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            error!(error = %e, "Failed to send error response");
            ResponseInfo::from(request.header().clone())
        }
    }
}
