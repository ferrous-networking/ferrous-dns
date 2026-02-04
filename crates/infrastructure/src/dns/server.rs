use ferrous_dns_application::use_cases::handle_dns_query::HandleDnsQueryUseCase;
use ferrous_dns_domain::{DnsRequest, RecordType};
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RData, Record, RecordType as HickoryRecordType};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::lookup::LookupRecordIter;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::Resolver;
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

    /// Normalize domain name by removing trailing dot (FQDN -> simple name)
    /// Example: "x.com." -> "x.com"
    fn normalize_domain(domain: &str) -> String {
        domain.trim_end_matches('.').to_string()
    }

    /// Get SOA record for AUTHORITY section in NODATA responses
    /// Returns empty vec if SOA lookup fails (graceful degradation)
    async fn get_soa_authority(&self, domain: &str) -> Vec<Record> {
        use hickory_proto::rr::RecordType as HickoryRecordType;

        // Create a quick resolver for SOA lookup
        let resolver = Resolver::builder_with_config(
            ResolverConfig::google(),
            TokioConnectionProvider::default(),
        )
        .build();

        // Try to lookup SOA record using generic lookup
        match resolver.lookup(domain, HickoryRecordType::SOA).await {
            Ok(lookup) => {
                let records: Vec<Record> =
                    LookupRecordIter::filter_map(lookup.record_iter(), |record| {
                        Some(record.clone())
                    })
                    .collect();

                if !records.is_empty() {
                    debug!(domain = %domain, count = records.len(), "SOA record found for AUTHORITY section");
                } else {
                    debug!(domain = %domain, "SOA lookup returned empty");
                }

                records
            }
            Err(e) => {
                debug!(domain = %domain, error = %e, "Failed to lookup SOA, using empty AUTHORITY");
                vec![]
            }
        }
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
                return send_error_response(request, &mut response_handle, ResponseCode::FormErr)
                    .await;
            }
        };

        let query = &request_info.query;
        let domain = Self::normalize_domain(&query.name().to_utf8());
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
            // Basic types
            HickoryRecordType::A => RecordType::A,
            HickoryRecordType::AAAA => RecordType::AAAA,
            HickoryRecordType::CNAME => RecordType::CNAME,
            HickoryRecordType::MX => RecordType::MX,
            HickoryRecordType::TXT => RecordType::TXT,
            HickoryRecordType::PTR => RecordType::PTR,

            // Advanced types
            HickoryRecordType::SRV => RecordType::SRV,
            HickoryRecordType::SOA => RecordType::SOA,
            HickoryRecordType::NS => RecordType::NS,
            HickoryRecordType::NAPTR => RecordType::NAPTR,
            HickoryRecordType::DS => RecordType::DS,
            HickoryRecordType::DNSKEY => RecordType::DNSKEY,
            HickoryRecordType::SVCB => RecordType::SVCB,
            HickoryRecordType::HTTPS => RecordType::HTTPS,

            // Security & Modern records
            HickoryRecordType::CAA => RecordType::CAA,
            HickoryRecordType::TLSA => RecordType::TLSA,
            HickoryRecordType::SSHFP => RecordType::SSHFP,
            // Note: DNAME not available in Hickory 0.25

            // DNSSEC records
            HickoryRecordType::RRSIG => RecordType::RRSIG,
            HickoryRecordType::NSEC => RecordType::NSEC,
            HickoryRecordType::NSEC3 => RecordType::NSEC3,
            HickoryRecordType::NSEC3PARAM => RecordType::NSEC3PARAM,

            // Child DNSSEC
            HickoryRecordType::CDS => RecordType::CDS,
            HickoryRecordType::CDNSKEY => RecordType::CDNSKEY,

            _ => {
                warn!(record_type = ?record_type, "Unsupported record type");
                return send_error_response(request, &mut response_handle, ResponseCode::NotImp)
                    .await;
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

        // If no addresses found, return NOERROR with SOA in AUTHORITY section
        // This is RFC 2308 compliant NODATA response
        if addresses.is_empty() {
            debug!(domain = %domain, record_type = ?record_type, "No records found (NODATA), fetching SOA");

            // Try to get SOA record for AUTHORITY section
            let authority_records = self.get_soa_authority(&domain).await;

            let builder = MessageResponseBuilder::from_message_request(request);
            
            // Set RA flag
            let mut header = *request.header();
            header.set_recursion_available(true);
            
            let response = builder.build(
                header,
                &[],                      // Empty answers
                authority_records.iter(), // SOA in authority section
                &[],
                &[],
            );

            return match response_handle.send_response(response).await {
                Ok(info) => info,
                Err(e) => {
                    error!(error = %e, "Failed to send NODATA response");
                    ResponseInfo::from(*request.header())
                }
            };
        }

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

        // Build response with RA (Recursion Available) flag
        let mut header = *request.header();
        header.set_recursion_available(true); // ✅ Indica que suportamos recursão
        
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
    header.set_recursion_available(true); // ✅ Sempre indicar suporte a recursão

    let response = builder.build(header, &[], &[], &[], &[]);

    match response_handle.send_response(response).await {
        Ok(info) => info,
        Err(e) => {
            error!(error = %e, "Failed to send error response");
            ResponseInfo::from(*request.header())
        }
    }
}
