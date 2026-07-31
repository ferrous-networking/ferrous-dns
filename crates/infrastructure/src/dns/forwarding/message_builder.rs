use super::record_type_map::RecordTypeMapper;
use super::response_validator::ResponseValidator;
use ferrous_dns_domain::{DomainError, RecordType};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::Name;
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use ring::rand::{SecureRandom, SystemRandom};
use std::str::FromStr;
use std::sync::LazyLock;

const CLIENT_COOKIE_LEN: usize = 8;
const COOKIE_OPTION_CODE: u16 = 10;

/// EDNS0 UDP payload size advertised on every outgoing upstream query.
///
/// 1232 is the DNS Flag Day 2020 recommendation: it fits inside the minimum
/// IPv6 MTU (1280) minus headers, so responses are never IP-fragmented. That
/// matters twice over — middleboxes routinely drop IP fragments (which shows up
/// as an unexplained timeout, not an error), and fragment-based cache poisoning
/// depends on the second fragment, which carries neither UDP header nor TXID.
/// Responses that no longer fit come back with TC=1 and are retried over TCP by
/// [`query_server`](crate::dns::load_balancer::query::query_server).
pub const EDNS_MAX_PAYLOAD: u16 = 1232;

/// Anti-spoofing measures for an upstream query, applied to every record type.
///
/// They used to be restricted to A/AAAA because other types are cached and
/// replayed to clients as raw upstream wire, which would have leaked our
/// randomized QNAME case. That leak is now closed at the source — responses are
/// canonicalized before they reach the cache (see
/// [`ResponseValidator::canonicalize`](super::ResponseValidator::canonicalize))
/// — so the restriction is gone. It mattered: DS/DNSKEY, MX/TXT (SPF/DKIM/DMARC)
/// and HTTPS/SVCB (ipv4hint/ipv6hint, ECH) were the least-protected queries in
/// the resolver.
#[derive(Clone, Copy, Debug, Default)]
pub struct HardeningOpts {
    /// Inject a random client DNS Cookie (RFC 7873, EDNS option 10) and validate
    /// its echo on the response.
    pub cookie: bool,
    /// Randomize QNAME letter case (draft-vixie-dns-0x20) and validate the echo.
    pub qname_0x20: bool,
}

pub struct MessageBuilder;

impl MessageBuilder {
    pub fn build_query(
        domain: &str,
        record_type: &RecordType,
        dnssec_ok: bool,
    ) -> Result<Vec<u8>, DomainError> {
        let (_, bytes) = Self::build_query_with_id(domain, record_type, dnssec_ok)?;
        Ok(bytes)
    }

    pub fn build_query_with_id(
        domain: &str,
        record_type: &RecordType,
        dnssec_ok: bool,
    ) -> Result<(u16, Vec<u8>), DomainError> {
        let name = Name::from_str(domain).map_err(|e| {
            DomainError::InvalidDomainName(format!("Invalid domain '{}': {}", domain, e))
        })?;
        let id = Self::secure_random_id();
        let bytes = Self::assemble_query(
            id,
            name,
            RecordTypeMapper::to_hickory(record_type),
            Self::build_edns(dnssec_ok),
        )?;
        Ok((id, bytes))
    }

    /// Builds an upstream query with optional anti-spoofing hardening and returns
    /// the wire bytes alongside a [`ResponseValidator`] capturing the per-query
    /// expectations (txid, question name/type, client cookie).
    ///
    /// Both measures apply to every record type; `opts` alone decides. Cookies
    /// are graceful (an upstream that does not echo one is accepted), so they are
    /// always on; 0x20 stays opt-in because some upstreams normalize QNAME case.
    /// Transaction-ID and question validation apply regardless.
    pub fn build_query_hardened(
        domain: &str,
        record_type: &RecordType,
        dnssec_ok: bool,
        opts: HardeningOpts,
    ) -> Result<(Vec<u8>, ResponseValidator), DomainError> {
        let use_cookie = opts.cookie;
        let use_0x20 = opts.qname_0x20;

        let name = if use_0x20 {
            Self::randomized_case_name(domain)?
        } else {
            Name::from_str(domain).map_err(|e| {
                DomainError::InvalidDomainName(format!("Invalid domain '{}': {}", domain, e))
            })?
        };

        let hickory_type = RecordTypeMapper::to_hickory(record_type);
        let id = Self::secure_random_id();

        let mut edns = Self::build_edns(dnssec_ok);
        let client_cookie = if use_cookie {
            let mut cookie = [0u8; CLIENT_COOKIE_LEN];
            Self::fill_random(&mut cookie);
            edns.options_mut()
                .insert(EdnsOption::Unknown(COOKIE_OPTION_CODE, cookie.to_vec()));
            Some(cookie)
        } else {
            None
        };

        let bytes = Self::assemble_query(id, name.clone(), hickory_type, edns)?;

        let expected_labels = name.iter().map(|label| label.to_vec()).collect();
        let validator =
            ResponseValidator::new(id, expected_labels, hickory_type, client_cookie, use_0x20);

        Ok((bytes, validator))
    }

    /// Builds a `Name` whose ASCII letters have randomized case (0x20). Built from
    /// raw label bytes via `Name::from_labels` because `Name::from_str` lowercases.
    fn randomized_case_name(domain: &str) -> Result<Name, DomainError> {
        // Parse first, then randomize the parsed labels. Splitting the input on
        // raw '.' instead would disagree with the non-randomized path on any name
        // where a dot is not a separator: `to_utf8` hands us DNS escapes, so
        // `a\.b.com` is two labels there and three here, and an IDN arrives as
        // punycode only through the parser. Querying a *different* name than the
        // caller asked for is invisible — the echo check compares against the same
        // wrong name, so it passes, and the answer is cached under the right key.
        let parsed = Name::from_str(domain).map_err(|e| {
            DomainError::InvalidDomainName(format!("Invalid domain '{}': {}", domain, e))
        })?;
        // The root has no labels to randomize, and `from_labels` rejects the empty
        // label a naive walk would produce. That matters more than it looks: the
        // DNSSEC chain bootstraps with a DNSKEY query for ".", so failing here
        // disables validation outright.
        if parsed.is_root() {
            return Ok(parsed);
        }

        let total: usize = parsed.iter().map(<[u8]>::len).sum();
        let mut rnd = vec![0u8; (total / 8) + 1];
        Self::fill_random(&mut rnd);

        let mut bit = 0usize;
        let mut labels: Vec<Vec<u8>> = Vec::new();
        for label in parsed.iter() {
            let mut current: Vec<u8> = Vec::with_capacity(label.len());
            for &b in label {
                if b.is_ascii_alphabetic() {
                    let uppercase = (rnd[bit / 8] >> (bit % 8)) & 1 == 1;
                    bit += 1;
                    current.push(if uppercase {
                        b.to_ascii_uppercase()
                    } else {
                        b.to_ascii_lowercase()
                    });
                } else {
                    current.push(b);
                }
            }
            labels.push(current);
        }

        Name::from_labels(labels).map_err(|e| {
            DomainError::InvalidDomainName(format!("Invalid domain '{}': {}", domain, e))
        })
    }

    fn fill_random(buf: &mut [u8]) {
        static SECURE_RNG: LazyLock<SystemRandom> = LazyLock::new(SystemRandom::new);
        if SECURE_RNG.fill(buf).is_err() {
            for b in buf.iter_mut() {
                *b = fastrand::u8(..);
            }
        }
    }

    fn secure_random_id() -> u16 {
        let mut bytes = [0u8; 2];
        Self::fill_random(&mut bytes);
        u16::from_be_bytes(bytes)
    }

    fn build_edns(dnssec_ok: bool) -> Edns {
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_MAX_PAYLOAD);
        edns.set_dnssec_ok(dnssec_ok);
        edns.set_version(0);
        edns
    }

    /// Assembles and serializes a recursion-desired query for `name`/`hickory_type`
    /// with the given EDNS. Shared boilerplate between the plain and hardened builders.
    fn assemble_query(
        id: u16,
        name: Name,
        hickory_type: hickory_proto::rr::RecordType,
        edns: Edns,
    ) -> Result<Vec<u8>, DomainError> {
        let mut query = Query::new();
        query.set_name(name);
        query.set_query_type(hickory_type);
        query.set_query_class(hickory_proto::rr::DNSClass::IN);

        let mut message = Message::new(id, MessageType::Query, OpCode::Query);
        message.metadata.recursion_desired = true;
        message.add_query(query);
        message.set_edns(edns);

        Self::serialize_message(&message)
    }

    fn serialize_message(message: &Message) -> Result<Vec<u8>, DomainError> {
        let mut buf = Vec::with_capacity(512);
        let mut encoder = BinEncoder::new(&mut buf);

        message.emit(&mut encoder).map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to serialize DNS message: {}", e))
        })?;

        Ok(buf)
    }
}
