use crate::dns::ede::{self, ExtendedDnsError};
use crate::dns::forwarding::RecordTypeMapper;
use crate::dns::wire_response;
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{BlockResponseMode, DnssecStatus, DomainError, RecordType};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::{RData, Record};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const DEFAULT_TTL: u32 = 60;

/// How domain-verdict blocks (blocklist, DGA, tunneling, C2 filter) are answered.
///
/// Snapshotted from `[blocking]` config at boot; applied to the wire response so
/// blocked answers become cacheable (default `NullIp`) instead of the legacy,
/// non-cacheable `REFUSED` that caused clients to retry aggressively.
#[derive(Debug, Clone, Copy)]
pub struct BlockPolicy {
    pub mode: BlockResponseMode,
    pub ttl: u32,
    /// Custom A target for `NullIp` blocks; `None` falls back to `0.0.0.0`.
    pub sinkhole_ipv4: Option<Ipv4Addr>,
    /// Custom AAAA target for `NullIp` blocks; `None` falls back to `::`.
    pub sinkhole_ipv6: Option<Ipv6Addr>,
}

#[derive(Clone)]
pub struct DnsServerHandler {
    use_case: Arc<HandleDnsQueryUseCase>,
    block_policy: BlockPolicy,
}

impl DnsServerHandler {
    pub fn new(use_case: Arc<HandleDnsQueryUseCase>, block_policy: BlockPolicy) -> Self {
        Self {
            use_case,
            block_policy,
        }
    }

    /// Normalizes a domain received from Hickory for downstream use: strips the
    /// trailing root dot and lowercases ASCII bytes (RFC 1035 §2.3.3 — DNS is
    /// case-insensitive). Returns `Cow::Borrowed` when the trimmed slice is
    /// already lowercase (zero-alloc fast path); otherwise owns a lowercased
    /// copy.
    fn normalize_domain(domain: &str) -> Cow<'_, str> {
        let trimmed = domain.trim_end_matches('.');
        if trimmed.bytes().all(|b| !b.is_ascii_uppercase()) {
            Cow::Borrowed(trimmed)
        } else {
            Cow::Owned(trimmed.to_ascii_lowercase())
        }
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

    /// Returns a ready-to-send cached wire response for non-IP record types (NS,
    /// CNAME, SOA, PTR, MX, TXT): the query ID is patched to `query_id` and the
    /// AD bit is cleared. Clearing AD here — rather than relying on every caller
    /// to do it — keeps the cached-wire fast path compliant for non-DO clients
    /// (RFC 6840 §5.8) by construction.
    pub fn try_fast_path_wire(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
        query_id: u16,
        client_max_size: u16,
    ) -> Option<(Vec<u8>, u32)> {
        let (wire, ttl) = self
            .use_case
            .try_cache_wire_direct(domain, record_type, client_ip)?;
        // Oversized-for-UDP hits bail to the slow path (handle_raw_udp_fallback),
        // which sets TC=1 — mirrors build_cache_hit_response for A/AAAA.
        if !wire_response::wire_fits_udp_buffer(wire.len(), client_max_size) {
            return None;
        }
        let patched = wire_response::patch_wire_id_clear_ad(&wire, query_id)?;
        Some((patched, ttl))
    }

    pub async fn handle_raw_udp_fallback(
        &self,
        raw: &[u8],
        client_ip: IpAddr,
        is_udp: bool,
    ) -> Option<Vec<u8>> {
        let query_msg = Message::from_vec(raw).ok()?;

        let queries: Vec<_> = query_msg.queries.to_vec();
        let query_info = queries.first()?;

        let domain_name = query_info.name().to_utf8();
        let domain_cow = Self::normalize_domain(&domain_name);
        let domain: &str = domain_cow.as_ref();
        let hickory_rt = query_info.query_type();

        let our_rt = RecordTypeMapper::from_hickory(hickory_rt)?;

        let query_id = query_msg.id;
        let rd = query_msg.recursion_desired;
        let cd = query_msg.checking_disabled;
        let has_edns = query_msg.edns.is_some();
        // RFC 6840 §5.8: only DNSSEC-aware clients (EDNS DO bit set) are eligible
        // for the AD bit in the response.
        let wants_dnssec = query_msg
            .edns
            .as_ref()
            .map(|edns| edns.flags().dnssec_ok)
            .unwrap_or(false);
        // Over UDP, the client-advertised EDNS buffer (or 512 without EDNS) caps
        // the response size; larger answers must be truncated with TC=1 so the
        // client retries over TCP. Not applicable to TCP/DoT/DoH.
        let udp_limit: Option<usize> = if is_udp {
            Some(
                query_msg
                    .edns
                    .as_ref()
                    .map(|edns| edns.max_payload() as usize)
                    .filter(|&size| size >= 512)
                    .unwrap_or(512),
            )
        } else {
            None
        };
        let edns_cookie: Option<Vec<u8>> = query_msg
            .edns
            .as_ref()
            .and_then(|edns| extract_edns_cookie(edns.options().as_ref().iter()));
        drop(query_msg);

        // Truncates an oversized UDP response down to a header-only TC=1 answer.
        let maybe_truncate = |bytes: Vec<u8>| -> Option<Vec<u8>> {
            match udp_limit {
                Some(limit) if bytes.len() > limit => build_truncated_wire(query_id, rd, &queries),
                _ => Some(bytes),
            }
        };

        let dns_request = {
            let base = ferrous_dns_domain::DnsRequest::new(domain, our_rt, client_ip)
                .with_checking_disabled(cd);
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
            | Err(ref e @ DomainError::FilteredQuery(_)) => {
                return build_blocked_wire(
                    query_id,
                    rd,
                    &queries,
                    self.block_policy,
                    has_edns,
                    ede::from_domain_error(e),
                )
            }
            Err(ref e @ DomainError::DnsRateLimited) => {
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

        // RFC 6840 §5.8: advertise Authenticated Data only to DNSSEC-aware clients
        // (DO bit), when we validated the answer as Secure, and the client did not
        // set CD (which signals it wants to do its own validation, not trust ours).
        let set_ad =
            wants_dnssec && !cd && resolution.dnssec_status == Some(DnssecStatus::Secure.as_str());

        let mut resp = Message::new(query_id, MessageType::Response, OpCode::Query);
        resp.metadata.recursion_desired = rd;
        resp.metadata.recursion_available = true;
        for q in &queries {
            resp.add_query(q.clone());
        }

        if addresses.is_empty() {
            if let Some(ref wire_data) = resolution.upstream_wire_data {
                // 0x20 case randomization no longer reaches this far: responses are
                // canonicalized at the upstream choke point, before they enter the
                // cache (see ResponseValidator::canonicalize). So the only reason
                // left to rebuild from the client's question is injecting our
                // server cookie; everything else keeps the raw-bytes fast path.
                let has_cookie_to_inject = dns_request
                    .edns_cookie
                    .as_ref()
                    .is_some_and(|c| c.len() >= 8);

                if has_cookie_to_inject {
                    match Message::from_vec(wire_data) {
                        Ok(upstream_msg) => {
                            resp.metadata.response_code = upstream_msg.response_code;
                            for record in &upstream_msg.answers {
                                resp.add_answer(record.clone());
                            }
                            for record in &upstream_msg.authorities {
                                resp.add_authority(record.clone());
                            }
                            for record in &upstream_msg.additionals {
                                // skip existing OPT — we add our own below
                                if record.record_type() != hickory_proto::rr::RecordType::OPT {
                                    resp.add_additional(record.clone());
                                }
                            }
                            // fall through to EDNS/cookie handling + encode resp below
                        }
                        Err(_) => {
                            // parse failed — fall back to raw bytes (id-patched)
                            let mut response = wire_data.to_vec();
                            if response.len() >= 2 {
                                response[0] = (query_id >> 8) as u8;
                                response[1] = query_id as u8;
                            }
                            wire_response::set_ad_bit(&mut response, set_ad);
                            return maybe_truncate(response);
                        }
                    }
                } else {
                    // No cookie to inject — raw bytes fast path. Note this hands
                    // the upstream's own OPT to the client verbatim, including the
                    // COOKIE option echoed back at us. Harmless (RFC 7873 §5.3 has
                    // clients ignore unsolicited cookies; ours is random per query
                    // and the server cookie is bound to our IP), and pre-existing —
                    // every upstream query has carried an OPT all along.
                    let mut response = wire_data.to_vec();
                    if response.len() >= 2 {
                        response[0] = (query_id >> 8) as u8;
                        response[1] = query_id as u8;
                    }
                    wire_response::set_ad_bit(&mut response, set_ad);
                    return maybe_truncate(response);
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
        resp.metadata.authentic_data = set_ad;

        maybe_truncate(encode_message(&resp)?)
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
    resp.metadata.recursion_desired = rd;
    resp.metadata.recursion_available = true;
    resp.metadata.response_code = code;
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

/// Synthesizes a minimal SOA record for the authority section of a negative
/// block answer (NXDOMAIN / NODATA), so resolvers can negatively cache it per
/// RFC 2308. The record TTL and the SOA `minimum` field are both set to the
/// block TTL, which bounds how long the negative answer is cached. `owner` is
/// the queried name; resolvers key the negative cache off the SOA `minimum`, so
/// an exact zone apex is not required for the synthetic answer.
fn synthetic_block_soa(owner: hickory_proto::rr::Name, ttl: u32) -> Record {
    use hickory_proto::rr::rdata::SOA;
    let rname = hickory_proto::rr::Name::from_ascii("hostmaster.ferrous-dns.invalid.")
        .unwrap_or_else(|_| hickory_proto::rr::Name::root());
    let soa = SOA::new(
        owner.clone(), // mname
        rname,         // rname
        1,             // serial
        3600,          // refresh
        600,           // retry
        604800,        // expire
        ttl,           // minimum — bounds the negative-cache TTL (RFC 2308)
    );
    Record::from_rdata(owner, ttl, RData::SOA(soa))
}

/// Builds the wire response for a domain-verdict block (raw UDP fast path),
/// honouring the configured [`BlockPolicy`]. `NullIp` synthesizes a cacheable
/// `0.0.0.0`/`::` answer (NODATA for non-A/AAAA queries); other modes set the
/// matching response code with an empty answer section. Negative answers
/// (NXDOMAIN / NODATA) carry a synthetic SOA so they can be negatively cached.
/// `Refused` delegates to [`build_error_wire`] for the legacy behaviour.
pub fn build_blocked_wire(
    id: u16,
    rd: bool,
    queries: &[hickory_proto::op::Query],
    policy: BlockPolicy,
    has_edns: bool,
    ede: Option<ExtendedDnsError>,
) -> Option<Vec<u8>> {
    use hickory_proto::rr::RecordType;

    if let BlockResponseMode::Refused = policy.mode {
        return build_error_wire(id, rd, queries, ResponseCode::Refused, has_edns, ede);
    }

    let mut resp = Message::new(id, MessageType::Response, OpCode::Query);
    resp.metadata.recursion_desired = rd;
    resp.metadata.recursion_available = true;
    for q in queries {
        resp.add_query(q.clone());
    }

    // True once we've emitted a positive answer; otherwise the response is a
    // negative answer (NXDOMAIN / NODATA) that should carry a synthetic SOA.
    let mut answered = false;

    match policy.mode {
        BlockResponseMode::NxDomain => {
            resp.metadata.response_code = ResponseCode::NXDomain;
        }
        BlockResponseMode::NoData => {
            resp.metadata.response_code = ResponseCode::NoError;
        }
        BlockResponseMode::NullIp => {
            resp.metadata.response_code = ResponseCode::NoError;
            if let Some(q) = queries.first() {
                let rdata = match q.query_type() {
                    RecordType::A => Some(RData::A(hickory_proto::rr::rdata::A(
                        policy.sinkhole_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
                    ))),
                    RecordType::AAAA => Some(RData::AAAA(hickory_proto::rr::rdata::AAAA(
                        policy.sinkhole_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED),
                    ))),
                    // Other record types: NODATA (NOERROR, empty answer).
                    _ => None,
                };
                if let Some(rdata) = rdata {
                    resp.add_answer(Record::from_rdata(q.name().clone(), policy.ttl, rdata));
                    answered = true;
                }
            }
        }
        // Handled above.
        BlockResponseMode::Refused => unreachable!(),
    }

    if !answered {
        if let Some(q) = queries.first() {
            resp.add_authority(synthetic_block_soa(q.name().clone(), policy.ttl));
        }
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
    resp.metadata.recursion_desired = rd;
    resp.metadata.recursion_available = true;
    resp.metadata.truncation = true;
    resp.metadata.response_code = ResponseCode::NoError;
    for q in queries {
        resp.add_query(q.clone());
    }
    encode_message(&resp)
}
