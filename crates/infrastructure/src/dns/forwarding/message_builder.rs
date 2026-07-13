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

/// Opt-in anti-spoofing measures for an upstream query. Only honored for A/AAAA
/// queries (see [`MessageBuilder::build_query_hardened`]); ignored for other
/// record types because their responses are cached/replayed as raw upstream wire
/// and must not carry randomized case or our cookie.
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
    /// Cookie injection and 0x20 case randomization are applied **only** to A/AAAA
    /// queries — for other record types the response is cached/replayed to clients
    /// as raw upstream wire, so randomized case or our cookie must not appear in it.
    /// Transaction-ID and question validation still apply to every query.
    pub fn build_query_hardened(
        domain: &str,
        record_type: &RecordType,
        dnssec_ok: bool,
        opts: HardeningOpts,
    ) -> Result<(Vec<u8>, ResponseValidator), DomainError> {
        let is_address = matches!(record_type, RecordType::A | RecordType::AAAA);
        let use_cookie = opts.cookie && is_address;
        let use_0x20 = opts.qname_0x20 && is_address;

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
        let src = domain.trim_end_matches('.').as_bytes();
        let mut rnd = vec![0u8; (src.len() / 8) + 1];
        Self::fill_random(&mut rnd);

        let mut bit = 0usize;
        let mut labels: Vec<Vec<u8>> = Vec::new();
        let mut current: Vec<u8> = Vec::new();
        for &b in src {
            if b == b'.' {
                labels.push(std::mem::take(&mut current));
            } else if b.is_ascii_alphabetic() {
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
        edns.set_max_payload(4096);
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
