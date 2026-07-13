use super::response_parser::DnsResponse;
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
/// them (i.e. for A/AAAA queries) AND the response arrived over plain-UDP/TCP
/// (Do53). Encrypted transports (DoT/DoH/DoQ) are authenticated by TLS, so their
/// echo is accepted case-insensitively even when 0x20 was applied to the wire.
/// Transaction-ID and question (name/type) matching always apply, across every
/// transport.
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

    fn spoof(&self, protocol: &DnsProtocol, reason: String) -> DomainError {
        DomainError::SpoofedResponse {
            server: protocol.to_string(),
            reason,
        }
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
