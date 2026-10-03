use crate::dns::cache::key::normalize_domain;
use crate::dns::ede::{self, ExtendedDnsError};
use crate::dns::fast_path::{self, FastPathQuery};
use crate::dns::forwarding::RecordTypeMapper;
use crate::dns::wire_response::{
    self, EdnsReply, QuestionName, Rcode, ResponseBody, ResponseHead, COOKIE_OPTION_CODE,
};
use ferrous_dns_application::use_cases::HandleDnsQueryUseCase;
use ferrous_dns_domain::{
    BlockResponseMode, ClientProtocol, DnsRequest, DnssecStatus, DomainError, EdnsCookie,
    RecordType,
};
use hickory_proto::op::{Message, MessageType, OpCode};
use hickory_proto::rr::rdata::opt::EdnsOption;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

const DEFAULT_TTL: u32 = 60;
/// The OPT a fast-path client with OPT and without a COOKIE gets: it has DO
/// clear, or the fast path would not serve it.
const PLAIN_EDNS: EdnsReply<'static> = EdnsReply {
    dnssec_ok: false,
    cookie: None,
    ede: None,
};

/// How domain-verdict blocks (blocklist, DGA, tunneling, C2 filter) are answered.
///
/// Snapshotted from `[blocking]` config at boot. The default `NullIp` makes a
/// blocked answer cacheable, so clients do not retry it the way they retry
/// `REFUSED`.
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

    /// Serves an A/AAAA cache hit through `respond`, which encodes the reply
    /// or declines it (`None`) for the slow path.
    pub fn try_fast_path<R>(
        &self,
        domain: &str,
        record_type: RecordType,
        client_ip: IpAddr,
        protocol: ClientProtocol,
        respond: impl FnOnce(&[IpAddr], u32) -> Option<R>,
    ) -> Option<R> {
        self.use_case
            .try_cache_direct(domain, record_type, client_ip, protocol, respond)
    }

    /// Returns a ready-to-send cached wire response for non-IP record types (NS,
    /// CNAME, SOA, PTR, MX, TXT, SRV, SVCB, HTTPS) under the query's ID and RD
    /// bit, with AD cleared: the fast path serves only non-DO clients (RFC 6840
    /// §5.8). Its TTLs count down the entry's time in the cache. `raw` is the
    /// query packet. `None` defers the query to the slow path, which then logs
    /// it instead.
    pub fn try_fast_path_wire(
        &self,
        query: &FastPathQuery,
        raw: &[u8],
        client_ip: IpAddr,
        protocol: ClientProtocol,
    ) -> Option<Vec<u8>> {
        self.use_case.try_cache_wire_direct(
            query.domain(),
            query.record_type,
            client_ip,
            protocol,
            |wire, remaining| {
                let reply = match query.edns_cookie(raw) {
                    None => wire_response::relay_cached(
                        wire,
                        query.id,
                        query.recursion_desired,
                        Some(query.question_name(raw)),
                        query.has_edns().then_some(&PLAIN_EDNS),
                        remaining,
                    ),
                    Some(cookie) => self
                        .relay_cached_with_cookie(wire, query, raw, cookie, client_ip, remaining),
                }?;
                // Oversized-for-UDP hits bail to the slow path, which sets TC=1,
                // as build_cache_hit_response does for A/AAAA.
                wire_response::wire_fits_udp_buffer(reply.len(), query.client_max_size)
                    .then_some(reply)
            },
        )
    }

    /// The cached answer for a client that sent `cookie`, which drops a reply
    /// that does not echo it (RFC 7873 §5.3). Out of line: the server cookie
    /// is an HMAC.
    #[inline(never)]
    fn relay_cached_with_cookie(
        &self,
        wire: &[u8],
        query: &FastPathQuery,
        raw: &[u8],
        cookie: &[u8],
        client_ip: IpAddr,
        remaining: u32,
    ) -> Option<Vec<u8>> {
        let cookie = self.response_cookie(Some(cookie), client_ip);
        let reply = EdnsReply {
            dnssec_ok: false,
            cookie: cookie.as_ref().map(EdnsCookie::as_bytes),
            ede: None,
        };
        wire_response::relay_cached(
            wire,
            query.id,
            query.recursion_desired,
            Some(query.question_name(raw)),
            Some(&reply),
            remaining,
        )
    }

    /// The resolution path for every query the inline cache path did not
    /// answer, over every transport. The query is decoded with the same wire
    /// parser as the cache fast path and the response is written straight to
    /// wire; hickory only parses queries that parser declines (IDN or escaped
    /// names, uncommon types, several questions), whose cache keys must match
    /// `Name::to_utf8()`.
    pub async fn handle_raw_udp_fallback(
        &self,
        raw: &[u8],
        client_ip: IpAddr,
        protocol: ClientProtocol,
    ) -> Option<Vec<u8>> {
        let (query, request) = match parse_client_query(raw, client_ip, protocol)? {
            ParsedQuery::Valid(query, request) => (query, request),
            ParsedQuery::BadCookie(query) => {
                return Some(query.respond(Rcode::FormErr, false, ResponseBody::Empty, None, None));
            }
        };

        // Over UDP, the client-advertised EDNS buffer (or 512 without EDNS) caps
        // the response size; larger answers must be truncated with TC=1 so the
        // client retries over TCP. TCP, DoT and DoH carry their own length
        // framing, and DoQ rides on UDP but frames responses explicitly (RFC
        // 9250), so none of them is subject to the limit.
        let udp_limit = matches!(protocol, ClientProtocol::Udp).then(|| {
            query
                .edns
                .map_or(512, |e| usize::from(e.udp_payload.max(512)))
        });
        let maybe_truncate = |bytes: Vec<u8>| match udp_limit {
            Some(limit) if bytes.len() > limit => query.truncated(),
            _ => bytes,
        };

        let resolution = match self.use_case.execute(&request).await {
            Ok(res) => res,
            // Over UDP the client retries a dropped query; a stream client
            // would sit out its timeout, so it gets SERVFAIL now.
            Err(DomainError::UpstreamCapacityExhausted) if protocol == ClientProtocol::Udp => {
                return None;
            }
            Err(e) => return Some(self.error_response(&query, request.record_type, &e)),
        };

        // RFC 6840 §5.8: advertise Authenticated Data only to DNSSEC-aware clients
        // (DO bit), when we validated the answer as Secure, and the client did not
        // set CD (which signals it wants to do its own validation, not trust ours).
        let set_ad = query.edns.is_some_and(|e| e.dnssec_ok)
            && !query.cd
            && resolution.dnssec_status == Some(DnssecStatus::Secure);
        let cookie = self.response_cookie(
            request.edns_cookie.as_ref().map(EdnsCookie::as_bytes),
            client_ip,
        );
        let cookie = cookie.as_ref().map(EdnsCookie::as_bytes);

        if resolution.addresses.is_empty() {
            if let Some(wire_data) = &resolution.upstream_wire_data {
                // 0x20 case randomization never reaches this far: responses are
                // canonicalized at the upstream choke point, before they enter
                // the cache (see ResponseValidator::canonicalize); the relay
                // writes the client's spelling back. Our OPT
                // replaces the upstream's or the cache's: DO copied from the
                // query (RFC 3225 §3), our server cookie, and none for a client
                // that sent none (RFC 6891 §7). A client without DO loses the
                // DNSSEC RRs it did not ask for (RFC 4035 §3.2.1).
                let reply = query.edns_reply(cookie, None);
                let qname = QuestionName::parse(&query.question);
                // A cache hit's TTLs count down its time in the cache (RFC
                // 1035 §3.2.1), as the fast path's do.
                let relayed = match (resolution.cache_hit, resolution.min_ttl) {
                    (true, Some(remaining)) => wire_response::relay_aged(
                        wire_data,
                        query.id,
                        query.rd,
                        qname,
                        set_ad,
                        reply.as_ref(),
                        remaining,
                    ),
                    _ => wire_response::relay_with_edns(
                        wire_data,
                        query.id,
                        query.rd,
                        qname,
                        set_ad,
                        reply.as_ref(),
                    ),
                };
                // A message that does not re-section (two OPTs, one outside
                // the additional section) or whose extended RCODE needs the
                // OPT a client without one cannot get: relaying it as is
                // would hand the client the upstream's OPT (RFC 6891 §7).
                return Some(match relayed {
                    Some(bytes) => maybe_truncate(bytes),
                    None => {
                        query.respond(Rcode::ServFail, false, ResponseBody::Empty, cookie, None)
                    }
                });
            }
        }

        let body = if resolution.addresses.is_empty() {
            ResponseBody::Empty
        } else {
            ResponseBody::Addresses {
                addresses: &resolution.addresses,
                ttl: resolution.min_ttl.unwrap_or(DEFAULT_TTL),
            }
        };
        Some(maybe_truncate(query.respond(
            Rcode::NoError,
            set_ad,
            body,
            cookie,
            None,
        )))
    }

    fn error_response(
        &self,
        query: &ClientQuery<'_>,
        record_type: RecordType,
        err: &DomainError,
    ) -> Vec<u8> {
        let ede = ede::from_domain_error(err);
        let rcode = match err {
            DomainError::Blocked
            | DomainError::DgaDomainDetected
            | DomainError::DnsTunnelingDetected
            | DomainError::FilteredQuery(_) => {
                return build_blocked_wire(query, record_type, self.block_policy, ede.as_ref());
            }
            DomainError::DnsRateLimitedSlip => return query.truncated(),
            DomainError::DnsRateLimited | DomainError::DnsCookieInvalid => Rcode::Refused,
            DomainError::NxDomain | DomainError::LocalNxDomain => {
                return query.respond(Rcode::NxDomain, false, ResponseBody::Empty, None, None);
            }
            _ => Rcode::ServFail,
        };
        query.respond(rcode, false, ResponseBody::Empty, None, ede.as_ref())
    }

    /// COOKIE option payload for the reply to `client_cookie`, the query's
    /// COOKIE option: the client cookie followed by our server cookie for it
    /// (RFC 7873 §5.2). `None` without a client cookie, or when DNS Cookies
    /// are disabled.
    fn response_cookie(
        &self,
        client_cookie: Option<&[u8]>,
        client_ip: IpAddr,
    ) -> Option<EdnsCookie> {
        let guard = self.use_case.cookie_guard()?;
        let client = client_cookie?.first_chunk::<8>()?;
        let server = guard.generate_server_cookie(client_ip, client);
        let mut payload = [0u8; 16];
        payload[..8].copy_from_slice(client);
        payload[8..].copy_from_slice(&server);
        EdnsCookie::from_bytes(&payload)
    }
}

/// The OPT fields of a client query that shape its response.
#[derive(Debug, Clone, Copy)]
struct ClientEdns {
    dnssec_ok: bool,
    udp_payload: u16,
}

/// What a response needs from its query, whichever parser decoded it.
pub struct ClientQuery<'a> {
    id: u16,
    rd: bool,
    cd: bool,
    /// `Some` iff the query carried OPT.
    edns: Option<ClientEdns>,
    /// Wire-format question section with an uncompressed first name.
    question: Cow<'a, [u8]>,
    qdcount: u16,
}

impl<'a> ClientQuery<'a> {
    /// A query with one uncompressed question, for building responses directly.
    pub fn new(id: u16, rd: bool, question: &'a [u8], edns_dnssec_ok: Option<bool>) -> Self {
        Self {
            id,
            rd,
            cd: false,
            edns: edns_dnssec_ok.map(|dnssec_ok| ClientEdns {
                dnssec_ok,
                udp_payload: 512,
            }),
            question: Cow::Borrowed(question),
            qdcount: 1,
        }
    }

    fn edns_reply<'r>(
        &self,
        cookie: Option<&'r [u8]>,
        ede: Option<&'r ExtendedDnsError>,
    ) -> Option<EdnsReply<'r>> {
        self.edns.map(|e| EdnsReply {
            dnssec_ok: e.dnssec_ok,
            cookie,
            ede,
        })
    }

    fn respond(
        &self,
        rcode: Rcode,
        authentic_data: bool,
        body: ResponseBody<'_>,
        cookie: Option<&[u8]>,
        ede: Option<&ExtendedDnsError>,
    ) -> Vec<u8> {
        let head = ResponseHead {
            id: self.id,
            recursion_desired: self.rd,
            authentic_data,
            rcode,
        };
        wire_response::encode_response(
            &head,
            &self.question,
            self.qdcount,
            body,
            self.edns_reply(cookie, ede).as_ref(),
        )
    }

    fn truncated(&self) -> Vec<u8> {
        wire_response::encode_truncated(self.id, self.rd, &self.question, self.qdcount)
    }
}

/// A decoded client query.
enum ParsedQuery<'a> {
    /// Resolve the request and answer in the query's shape.
    Valid(ClientQuery<'a>, DnsRequest),
    /// RFC 7873 §5.2.2: a COOKIE option of a length it does not allow is
    /// answered with FORMERR.
    BadCookie(ClientQuery<'a>),
}

/// Decodes a client query into its response shape and the resolver request.
/// `None` drops the query: it is malformed, or of a type we do not resolve.
fn parse_client_query(
    raw: &[u8],
    client_ip: IpAddr,
    protocol: ClientProtocol,
) -> Option<ParsedQuery<'_>> {
    // The wire parser declines options it cannot walk, and bad COOKIEs, so
    // hickory's decoder has the last word on both.
    let Some(q) = fast_path::parse_query(raw) else {
        return parse_client_query_hickory(raw, client_ip, protocol);
    };
    let mut request = DnsRequest::new(q.domain(), q.record_type, client_ip)
        .with_checking_disabled(q.checking_disabled)
        .with_protocol(protocol);
    if let Some(cookie) = q.edns_cookie(raw).and_then(EdnsCookie::from_bytes) {
        request = request.with_cookie(cookie);
    }
    let query = ClientQuery {
        id: q.id,
        rd: q.recursion_desired,
        cd: q.checking_disabled,
        edns: q.has_edns().then_some(ClientEdns {
            dnssec_ok: q.wants_dnssec,
            udp_payload: q.client_max_size,
        }),
        question: Cow::Borrowed(q.question(raw)),
        qdcount: 1,
    };
    Some(ParsedQuery::Valid(query, request))
}

fn parse_client_query_hickory(
    raw: &[u8],
    client_ip: IpAddr,
    protocol: ClientProtocol,
) -> Option<ParsedQuery<'static>> {
    let mut msg = Message::from_vec(raw).ok()?;
    let first = msg.queries.first()?;
    let record_type = RecordTypeMapper::from_hickory(first.query_type())?;
    let domain_name = first.name().to_utf8();
    let domain = normalize_domain(domain_name.trim_end_matches('.'));

    let mut request = DnsRequest::new(domain.as_ref(), record_type, client_ip)
        .with_checking_disabled(msg.checking_disabled)
        .with_protocol(protocol);
    let cookie = msg.edns.as_ref().and_then(|edns| {
        edns.options()
            .as_ref()
            .iter()
            .find_map(|(_, opt)| match opt {
                EdnsOption::Unknown(COOKIE_OPTION_CODE, data) => Some(data.as_slice()),
                _ => None,
            })
    });
    let cookie = cookie.map(EdnsCookie::from_bytes);
    if let Some(Some(cookie)) = cookie {
        request = request.with_cookie(cookie);
    }

    // Re-encoded behind a header so any compression pointer hickory emits is
    // relative to the message start, exactly where the response places it.
    let qdcount = u16::try_from(msg.queries.len()).ok()?;
    let mut questions = Message::new(0, MessageType::Query, OpCode::Query);
    questions.add_queries(std::mem::take(&mut msg.queries));
    let mut question = questions.to_vec().ok()?;
    question.drain(..12);

    let query = ClientQuery {
        id: msg.id,
        rd: msg.recursion_desired,
        cd: msg.checking_disabled,
        edns: msg.edns.as_ref().map(|edns| ClientEdns {
            dnssec_ok: edns.flags().dnssec_ok,
            udp_payload: edns.max_payload(),
        }),
        question: Cow::Owned(question),
        qdcount,
    };
    Some(match cookie {
        Some(None) => ParsedQuery::BadCookie(query),
        Some(Some(_)) | None => ParsedQuery::Valid(query, request),
    })
}

/// Builds the response for a domain-verdict block, honouring the configured
/// [`BlockPolicy`]. `NullIp` synthesizes a cacheable `0.0.0.0`/`::` answer
/// (NODATA for non-A/AAAA queries); other modes set the matching response
/// code with an empty answer section. Negative answers (NXDOMAIN / NODATA)
/// carry a synthetic SOA so they can be negatively cached; `Refused` carries
/// none.
pub fn build_blocked_wire(
    query: &ClientQuery<'_>,
    record_type: RecordType,
    policy: BlockPolicy,
    ede: Option<&ExtendedDnsError>,
) -> Vec<u8> {
    let negative = ResponseBody::NegativeSoa { ttl: policy.ttl };
    let (rcode, sinkhole) = match policy.mode {
        BlockResponseMode::Refused => {
            return query.respond(Rcode::Refused, false, ResponseBody::Empty, None, ede);
        }
        BlockResponseMode::NxDomain => (Rcode::NxDomain, None),
        BlockResponseMode::NoData => (Rcode::NoError, None),
        BlockResponseMode::NullIp => (
            Rcode::NoError,
            match record_type {
                RecordType::A => Some(IpAddr::V4(
                    policy.sinkhole_ipv4.unwrap_or(Ipv4Addr::UNSPECIFIED),
                )),
                RecordType::AAAA => Some(IpAddr::V6(
                    policy.sinkhole_ipv6.unwrap_or(Ipv6Addr::UNSPECIFIED),
                )),
                _ => None,
            },
        ),
    };
    let body = match sinkhole.as_ref() {
        Some(address) => ResponseBody::Addresses {
            addresses: std::slice::from_ref(address),
            ttl: policy.ttl,
        },
        None => negative,
    };
    query.respond(rcode, false, body, None, ede)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));

    /// `(flags, name, qtype, OPT as (payload, DO, options))`
    type Case = (u16, &'static str, u16, Option<(u16, bool, &'static [u8])>);

    fn valid(parsed: Option<ParsedQuery<'_>>) -> (ClientQuery<'_>, DnsRequest) {
        match parsed {
            Some(ParsedQuery::Valid(query, request)) => (query, request),
            Some(ParsedQuery::BadCookie(_)) => panic!("COOKIE rejected"),
            None => panic!("query dropped"),
        }
    }

    fn encode(id: u16, (flags, name, qtype, opt): Case) -> Vec<u8> {
        let mut buf = id.to_be_bytes().to_vec();
        buf.extend_from_slice(&flags.to_be_bytes());
        buf.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, u8::from(opt.is_some())]);
        for label in name.split('.').filter(|l| !l.is_empty()) {
            buf.push(label.len() as u8);
            buf.extend_from_slice(label.as_bytes());
        }
        buf.push(0);
        buf.extend_from_slice(&qtype.to_be_bytes());
        buf.extend_from_slice(&[0, 1]);
        if let Some((payload, dnssec_ok, options)) = opt {
            buf.extend_from_slice(&[0, 0, 41]);
            buf.extend_from_slice(&payload.to_be_bytes());
            buf.extend_from_slice(&[0, 0, u8::from(dnssec_ok) << 7, 0]);
            buf.extend_from_slice(&(options.len() as u16).to_be_bytes());
            buf.extend_from_slice(options);
        }
        buf
    }

    /// Every field the slow path reads must decode the same through the wire
    /// parser as through hickory, or answers would depend on which one ran.
    #[test]
    fn wire_parse_matches_hickory_parse() {
        const COOKIE: &[u8] = &[0, 10, 0, 8, 1, 2, 3, 4, 5, 6, 7, 8];
        const COOKIE_AFTER_PADDING: &[u8] = &[
            0, 12, 0, 3, 0, 0, 0, // padding
            0, 10, 0, 24, 9, 9, 9, 9, 9, 9, 9, 9, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2,
        ];
        let cases: &[Case] = &[
            (0x0100, "example.com", 1, None),
            (0x0000, "Example.COM", 28, None),
            (0x0110, "a.b.example.com", 1, Some((1232, false, &[]))),
            (0x0100, "example.com", 15, Some((4096, true, COOKIE))),
            (
                0x0130,
                "_dmarc.example.com",
                16,
                Some((300, true, COOKIE_AFTER_PADDING)),
            ),
            (0x0100, "", 2, Some((512, false, COOKIE))),
        ];
        for (i, &case) in cases.iter().enumerate() {
            let raw = encode(0x4000 + i as u16, case);
            assert!(fast_path::parse_query(&raw).is_some(), "case {i}");
            let (wq, wr) = valid(parse_client_query(&raw, CLIENT, ClientProtocol::Udp));
            let (hq, hr) = valid(parse_client_query_hickory(
                &raw,
                CLIENT,
                ClientProtocol::Udp,
            ));

            assert_eq!(wr.domain, hr.domain, "case {i}");
            assert_eq!(wr.record_type, hr.record_type, "case {i}");
            assert_eq!(wr.checking_disabled, hr.checking_disabled, "case {i}");
            assert_eq!(
                wr.edns_cookie.as_ref().map(EdnsCookie::as_bytes),
                hr.edns_cookie.as_ref().map(EdnsCookie::as_bytes),
                "case {i}"
            );
            assert_eq!((wq.id, wq.rd, wq.cd), (hq.id, hq.rd, hq.cd), "case {i}");
            assert_eq!(
                wq.edns.map(|e| (e.dnssec_ok, e.udp_payload.max(512))),
                hq.edns.map(|e| (e.dnssec_ok, e.udp_payload.max(512))),
                "case {i}"
            );
            assert_eq!(
                (&*wq.question, wq.qdcount),
                (&*hq.question, hq.qdcount),
                "case {i}"
            );
        }
    }

    /// What a parse decided, comparable across the two parsers.
    fn outcome(parsed: Option<ParsedQuery<'_>>) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        parsed.map(|parsed| match parsed {
            ParsedQuery::Valid(q, r) => (
                q.question.into_owned(),
                r.edns_cookie.map(|c| c.as_bytes().to_vec()),
            ),
            ParsedQuery::BadCookie(q) => (q.question.into_owned(), None),
        })
    }

    #[test]
    fn malformed_edns_options_are_decoded_by_hickory() {
        // Option length 8 with 4 bytes present: the wire parser declines, and
        // the query is decoded exactly as hickory decodes it.
        let raw = encode(
            1,
            (
                0x0100,
                "example.com",
                1,
                Some((1232, false, &[0, 10, 0, 8, 1, 2, 3, 4])),
            ),
        );
        assert!(fast_path::parse_query(&raw).is_none());
        assert_eq!(
            outcome(parse_client_query(&raw, CLIENT, ClientProtocol::Udp)),
            outcome(parse_client_query_hickory(
                &raw,
                CLIENT,
                ClientProtocol::Udp
            ))
        );
    }

    /// RFC 7873 §5.2.2: a COOKIE that is not 8 or 16..=40 bytes is a FORMERR,
    /// never a cookie cut down to fit. The cache fast path must not answer it
    /// either, so its parser declines the query.
    #[test]
    fn cookies_of_a_disallowed_length_are_rejected_by_both_parsers() {
        for len in [0usize, 7, 9, 15, 41, 64] {
            let mut option = vec![0, 10];
            option.extend_from_slice(&(len as u16).to_be_bytes());
            option.extend(std::iter::repeat_n(0xAB, len));
            let option: &'static [u8] = option.leak();
            let raw = encode(1, (0x0100, "example.com", 1, Some((1232, false, option))));

            assert!(fast_path::parse_query(&raw).is_none(), "{len} bytes");
            assert!(
                matches!(
                    parse_client_query(&raw, CLIENT, ClientProtocol::Udp),
                    Some(ParsedQuery::BadCookie(_))
                ),
                "{len} bytes"
            );
        }
        for len in [8usize, 16, 40] {
            let mut option = vec![0, 10];
            option.extend_from_slice(&(len as u16).to_be_bytes());
            option.extend(std::iter::repeat_n(0xAB, len));
            let option: &'static [u8] = option.leak();
            let raw = encode(1, (0x0100, "example.com", 1, Some((1232, false, option))));
            let (_, request) = valid(parse_client_query(&raw, CLIENT, ClientProtocol::Udp));
            assert_eq!(
                request.edns_cookie.map(|c| c.as_bytes().len()),
                Some(len),
                "{len} bytes"
            );
        }
    }

    /// RFC 6891 §6.1.1 makes two OPT records a FORMERR. The wire parser must
    /// decline such a query, or the cache fast path would answer what hickory
    /// rejects; both routes then treat it identically.
    #[test]
    fn query_with_two_opt_records_is_left_to_hickory() {
        let mut raw = encode(1, (0x0100, "example.com", 1, Some((1232, false, &[]))));
        raw.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
        raw[11] = 2;

        assert!(fast_path::parse_query(&raw).is_none());
        assert_eq!(
            outcome(parse_client_query(&raw, CLIENT, ClientProtocol::Udp)),
            outcome(parse_client_query_hickory(
                &raw,
                CLIENT,
                ClientProtocol::Udp
            ))
        );
    }
}
