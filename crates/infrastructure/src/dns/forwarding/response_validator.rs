use super::response_parser::DnsResponse;
use bytes::Bytes;
use ferrous_dns_domain::{DnsProtocol, DomainError};
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RecordType as HickoryRecordType};

const CLIENT_COOKIE_LEN: usize = 8;
const COOKIE_OPTION_CODE: u16 = 10;

/// Per-query expectations used to reject spoofed/off-path upstream responses on
/// the plain-UDP/TCP (Do53) path. Produced by
/// [`MessageBuilder::build_query_hardened`](super::message_builder::MessageBuilder::build_query_hardened)
/// and checked at the single upstream choke point after the response is parsed.
///
/// Cookie and case-sensitive (0x20) checks only apply when the builder injected
/// them AND the response arrived over plain-UDP/TCP (Do53). Encrypted transports
/// (DoT/DoH/DoQ) are authenticated by TLS, so their echo is accepted
/// case-insensitively even when 0x20 was applied to the wire. Transaction-ID and
/// question (name/type) matching always apply, across every transport.
pub struct ResponseValidator {
    id: u16,
    /// Case-preserving label bytes of the question name we sent.
    expected_labels: Vec<Vec<u8>>,
    expected_qtype: HickoryRecordType,
    /// `Some` only when a client cookie (EDNS option 10) was sent.
    client_cookie: Option<[u8; CLIENT_COOKIE_LEN]>,
    /// `true` when 0x20 case randomization was applied — compare labels case-sensitively.
    case_sensitive: bool,
}

impl ResponseValidator {
    pub fn new(
        id: u16,
        expected_labels: Vec<Vec<u8>>,
        expected_qtype: HickoryRecordType,
        client_cookie: Option<[u8; CLIENT_COOKIE_LEN]>,
        case_sensitive: bool,
    ) -> Self {
        Self {
            id,
            expected_labels,
            expected_qtype,
            client_cookie,
            case_sensitive,
        }
    }

    /// Validates a parsed upstream response against this query's expectations.
    /// Returns [`DomainError::SpoofedResponse`] (transport-class, so strategies
    /// fail over to the next server) on any mismatch.
    pub fn validate(&self, resp: &DnsResponse, protocol: &DnsProtocol) -> Result<(), DomainError> {
        let msg = &resp.message;

        if msg.id != self.id {
            return Err(self.spoof(
                protocol,
                format!(
                    "transaction ID mismatch: expected {:#06x}, got {:#06x}",
                    self.id, msg.id
                ),
            ));
        }

        let query = msg
            .queries
            .first()
            .ok_or_else(|| self.spoof(protocol, "response has no question section".to_string()))?;

        if query.query_type() != self.expected_qtype {
            return Err(self.spoof(
                protocol,
                format!(
                    "question type mismatch: expected {:?}, got {:?}",
                    self.expected_qtype,
                    query.query_type()
                ),
            ));
        }

        if !self.qname_matches(query.name(), protocol) {
            return Err(self.spoof(protocol, "question name mismatch".to_string()));
        }

        // Cookie echo only protects plain-UDP/TCP upstreams; encrypted transports
        // are already authenticated by TLS.
        if let Some(ref expected) = self.client_cookie {
            if is_do53(protocol) {
                self.validate_cookie(msg, protocol, expected)?;
            }
        }

        Ok(())
    }

    /// Compares the response question labels to what we sent. hickory `Name`
    /// equality is case-INSENSITIVE, so we compare label bytes ourselves —
    /// case-sensitively only when 0x20 was applied AND the response is Do53
    /// (encrypted transports are TLS-authenticated, so we tolerate upstreams that
    /// normalize QNAME case); otherwise ASCII-case-insensitively.
    fn qname_matches(&self, name: &Name, protocol: &DnsProtocol) -> bool {
        let mut got = name.iter();
        let mut want = self.expected_labels.iter();
        loop {
            match (got.next(), want.next()) {
                (Some(g), Some(w)) => {
                    let eq = if self.case_sensitive && is_do53(protocol) {
                        g == w.as_slice()
                    } else {
                        g.eq_ignore_ascii_case(w)
                    };
                    if !eq {
                        return false;
                    }
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }

    fn validate_cookie(
        &self,
        msg: &Message,
        protocol: &DnsProtocol,
        expected: &[u8; CLIENT_COOKIE_LEN],
    ) -> Result<(), DomainError> {
        let echoed = msg
            .edns
            .as_ref()
            .and_then(|edns| extract_cookie(edns.options().as_ref().iter()));

        match echoed {
            // Graceful: upstream did not echo a cookie (no DNS Cookies support).
            None => Ok(()),
            Some(data) if data.len() < CLIENT_COOKIE_LEN => Err(self.spoof(
                protocol,
                format!("malformed cookie option ({} bytes)", data.len()),
            )),
            Some(data) => {
                use subtle::ConstantTimeEq;
                if bool::from(data[..CLIENT_COOKIE_LEN].ct_eq(&expected[..])) {
                    Ok(())
                } else {
                    Err(self.spoof(protocol, "client cookie echo mismatch".to_string()))
                }
            }
        }
    }

    /// Strips our 0x20 case randomization from a validated response, in place.
    ///
    /// MUST run after [`validate`](Self::validate): the randomized case *is* the
    /// evidence that check consumes, and this destroys it.
    ///
    /// Canonical here means lowercase, not "whatever the client sent" — the
    /// server lowercases the queried name on ingress, so by the time a query
    /// reaches an upstream the client's case is already gone. Doing this at the
    /// upstream choke point rather than on the way out to the client is what
    /// covers the cached-wire path, which replays bytes straight from the cache
    /// without ever re-parsing them.
    pub fn canonicalize(&self, resp: &mut DnsResponse) {
        if !self.case_sensitive {
            return;
        }

        if let Some(canonical) = lowercase_owner_names(&resp.raw_bytes) {
            resp.raw_bytes = canonical;
        }

        for query in resp.message.queries.iter_mut() {
            let lower = query.name().to_lowercase();
            query.set_name(lower);
        }
        for record in resp
            .message
            .answers
            .iter_mut()
            .chain(resp.message.authorities.iter_mut())
            .chain(resp.message.additionals.iter_mut())
            .chain(resp.raw_answers.iter_mut())
        {
            record.name = record.name.to_lowercase();
        }
    }

    fn spoof(&self, protocol: &DnsProtocol, reason: String) -> DomainError {
        DomainError::SpoofedResponse {
            server: protocol.to_string(),
            reason,
        }
    }
}

/// Lowercases every owner name in a raw response — the question QNAME plus the
/// owner of each resource record — returning a rewritten buffer only when
/// something actually changed.
///
/// Walking only the question is not enough, though it is tempting: owner names
/// elsewhere are *usually* compression pointers back to it. Not always. An
/// upstream is free to write them literally, and compression pointers are
/// 14-bit, so any name past offset 16383 of a large answer — DNSKEY, RRSIG, TXT,
/// exactly the types 0x20 was just extended to — cannot be compressed at all.
/// Those literal copies carry our randomized case into the cache and back out to
/// clients.
///
/// Rdata is skipped wholesale via its length field rather than parsed. The names
/// that can echo our randomized QNAME are owner names; names buried in rdata
/// (a CNAME target, an RRSIG signer) are zone data we never influenced. Skipping
/// keeps this independent of record types. Case changes preserve length, so it
/// stays a byte fixup with no header, rdlength or pointer offsets to repair.
fn lowercase_owner_names(wire: &Bytes) -> Option<Bytes> {
    const HEADER_LEN: usize = 12;

    let count = |at: usize| -> Option<usize> {
        Some(u16::from_be_bytes([*wire.get(at)?, *wire.get(at + 1)?]) as usize)
    };
    let (qdcount, ancount, nscount, arcount) = (count(4)?, count(6)?, count(8)?, count(10)?);

    let mut labels: Vec<(usize, usize)> = Vec::new();
    let mut pos = HEADER_LEN;

    for _ in 0..qdcount {
        pos = walk_name(wire, pos, &mut labels)?;
        // QTYPE + QCLASS
        pos = pos.checked_add(4)?;
    }
    for _ in 0..(ancount + nscount + arcount) {
        pos = walk_name(wire, pos, &mut labels)?;
        // TYPE + CLASS + TTL, then the RDLENGTH that tells us how far to jump.
        let rdlength_at = pos.checked_add(8)?;
        let rdlength = count(rdlength_at)?;
        pos = rdlength_at.checked_add(2)?.checked_add(rdlength)?;
    }
    if pos > wire.len() {
        return None;
    }

    if !labels
        .iter()
        .any(|(start, end)| wire[*start..*end].iter().any(u8::is_ascii_uppercase))
    {
        return None;
    }

    let mut buf = wire.to_vec();
    for (start, end) in labels {
        buf[start..end].make_ascii_lowercase();
    }
    Some(Bytes::from(buf))
}

/// Walks one wire-format name starting at `pos`, recording the byte range of
/// each literal label, and returns the offset just past the name.
///
/// A compression pointer terminates the name and needs no rewriting of its own:
/// it aims at an earlier occurrence, whose literal labels this walk records when
/// it reaches them. Anything malformed returns `None`, which leaves the whole
/// buffer untouched rather than rewriting bytes we have not understood.
fn walk_name(wire: &Bytes, mut pos: usize, labels: &mut Vec<(usize, usize)>) -> Option<usize> {
    loop {
        let len = *wire.get(pos)? as usize;
        if len == 0 {
            return pos.checked_add(1);
        }
        if len & 0xC0 == 0xC0 {
            wire.get(pos + 1)?;
            return pos.checked_add(2);
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let (start, end) = (pos + 1, pos + 1 + len);
        if end > wire.len() {
            return None;
        }
        labels.push((start, end));
        pos = end;
    }
}

fn is_do53(protocol: &DnsProtocol) -> bool {
    matches!(protocol, DnsProtocol::Udp { .. } | DnsProtocol::Tcp { .. })
}

fn extract_cookie<'a>(
    mut options: impl Iterator<Item = &'a (EdnsCode, EdnsOption)>,
) -> Option<Vec<u8>> {
    options.find_map(|(_, opt)| match opt {
        EdnsOption::Unknown(COOKIE_OPTION_CODE, data) => Some(data.clone()),
        _ => None,
    })
}
