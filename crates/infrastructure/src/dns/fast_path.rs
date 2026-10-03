use super::wire_response::{QuestionName, COOKIE_OPTION_CODE};
use ferrous_dns_domain::{EdnsCookie, RecordType};

const MAX_DOMAIN_LEN: usize = 253;

/// Distinguishes A/AAAA queries (served inline via `build_cache_hit_response`)
/// from other record types whose cached form is the upstream response.
pub enum FastPathKind {
    /// A (1) or AAAA (28) — address records, served inline without heap alloc.
    IpAddress,
    /// NS (2), CNAME (5), SOA (6), PTR (12), MX (15), TXT (16), HTTPS (65),
    /// SRV (33), SVCB (64) — cached as `CachedData::WireData`; served by
    /// re-issuing that response under the query's header and OPT.
    WireData,
}

pub struct FastPathQuery {
    pub id: u16,
    pub record_type: RecordType,
    /// How this query's cache hit should be served.
    pub kind: FastPathKind,
    pub question_end: usize,
    pub client_max_size: u16,
    /// The client set the EDNS DO bit — it is DNSSEC-aware and expects the AD
    /// bit / validation to be honoured. Such queries skip the inline cache fast
    /// path (which cannot set AD) and take the full resolver path instead.
    pub wants_dnssec: bool,
    pub recursion_desired: bool,
    pub checking_disabled: bool,
    /// `Some` iff the query carried OPT.
    opt: Option<QueryOpt>,
    domain_buf: [u8; MAX_DOMAIN_LEN + 1],
    domain_len: usize,
}

/// What the fast path answers from a query's OPT, whose option sequence is
/// well formed.
#[derive(Clone, Copy)]
struct QueryOpt {
    /// `(offset, len)` in the query buffer of the first COOKIE option's data.
    cookie: Option<(usize, usize)>,
}

impl FastPathQuery {
    #[inline]
    pub fn has_edns(&self) -> bool {
        self.opt.is_some()
    }

    pub fn domain(&self) -> &str {
        // SAFETY: `parse_query` only copies ASCII alphanumerics, `_`, `-`, `*`
        // and `.` into `domain_buf[..domain_len]`, so it is valid UTF-8.
        unsafe { core::str::from_utf8_unchecked(&self.domain_buf[..self.domain_len]) }
    }

    /// The question section, `buf[12..question_end]`, for echoing in a response.
    pub fn question<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        &buf[12..self.question_end]
    }

    /// The question name, `buf[12..question_end - 4]`, which `parse_query`
    /// walked label by label, so it needs no second walk.
    #[inline]
    pub fn question_name<'a>(&self, buf: &'a [u8]) -> QuestionName<'a> {
        QuestionName(&buf[12..self.question_end - 4])
    }

    /// The first DNS Cookie option (RFC 7873, code 10) of the query in `buf`,
    /// the packet this was parsed from.
    #[inline]
    pub fn edns_cookie<'a>(&self, buf: &'a [u8]) -> Option<&'a [u8]> {
        let (start, len) = self.opt?.cookie?;
        buf.get(start..start + len)
    }
}

/// Reads the options of an OPT whose RDATA is `buf[start..start + len]`.
/// `None` unless they decode as a sequence of EDNS options (RFC 6891
/// §6.1.2) whose COOKIEs have a length RFC 7873 allows: anything else is
/// left to the slow path, which decodes it with hickory and answers a bad
/// COOKIE with FORMERR (RFC 7873 §5.2.2).
#[inline]
fn parse_opt_options(buf: &[u8], start: usize, len: usize) -> Option<QueryOpt> {
    let end = start + len;
    buf.get(start..end)?;
    let mut at = start;
    let mut cookie = None;
    while at < end {
        let [c0, c1, l0, l1] = *buf.get(at..)?.first_chunk::<4>()?;
        let data = at + 4;
        let data_len = usize::from(u16::from_be_bytes([l0, l1]));
        at = data + data_len;
        if at > end {
            return None;
        }
        if u16::from_be_bytes([c0, c1]) == COOKIE_OPTION_CODE {
            if !EdnsCookie::is_valid_len(data_len) {
                return None;
            }
            cookie.get_or_insert((data, data_len));
        }
    }
    Some(QueryOpt { cookie })
}

pub fn parse_query(buf: &[u8]) -> Option<FastPathQuery> {
    if buf.len() < 17 {
        return None;
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);

    if flags & 0xF800 != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    let ancount = u16::from_be_bytes([buf[6], buf[7]]);
    let nscount = u16::from_be_bytes([buf[8], buf[9]]);
    let arcount = u16::from_be_bytes([buf[10], buf[11]]);

    if qdcount != 1 || ancount != 0 || nscount != 0 {
        return None;
    }

    let mut pos = 12;
    let mut domain_buf = [0u8; MAX_DOMAIN_LEN + 1];
    let mut domain_len = 0usize;
    let mut first_label = true;

    loop {
        if pos >= buf.len() {
            return None;
        }
        let label_len = buf[pos] as usize;
        if label_len == 0 {
            pos += 1;
            break;
        }
        if label_len & 0xC0 != 0 {
            return None;
        }
        pos += 1;
        if pos + label_len > buf.len() {
            return None;
        }
        if !first_label {
            if domain_len >= MAX_DOMAIN_LEN {
                return None;
            }
            domain_buf[domain_len] = b'.';
            domain_len += 1;
        }
        first_label = false;
        if domain_len + label_len > MAX_DOMAIN_LEN {
            return None;
        }
        // The slow path keys the cache on hickory's `Name::to_utf8()`, which
        // decodes an A-label back to Unicode (`xn--bcher-kva` -> `bücher`).
        // Copying it verbatim would key the same query two different ways, so
        // IDN names belong to the slow path.
        if label_len >= 4 && buf[pos..pos + 4].eq_ignore_ascii_case(b"xn--") {
            return None;
        }
        for (i, &b) in buf[pos..pos + label_len].iter().enumerate() {
            // Only bytes hickory leaves unescaped may be copied verbatim. Its
            // `Label::is_safe_ascii` keeps ASCII alphanumerics, `_`, `-` when
            // it is not the first byte of the label, and a leading `*`;
            // everything else comes back as `\c` or `\DDD`, which is a
            // different cache key for the same wire name. A literal `.` would
            // also collide with the multi-label name that reads the same once
            // `domain_buf` is flattened, and a non-UTF-8 byte would make
            // `domain()` fall back to the empty string. All of those go to the
            // slow path, which parses them with hickory.
            let unescaped = b.is_ascii_alphanumeric()
                || b == b'_'
                || (b == b'-' && i != 0)
                || (b == b'*' && i == 0);
            if !unescaped {
                return None;
            }
            domain_buf[domain_len] = b.to_ascii_lowercase();
            domain_len += 1;
        }
        pos += label_len;
    }

    if pos + 4 > buf.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);
    pos += 4;

    if qclass != 1 {
        return None;
    }

    let (record_type, kind) = match qtype {
        1 => (RecordType::A, FastPathKind::IpAddress),
        2 => (RecordType::NS, FastPathKind::WireData),
        5 => (RecordType::CNAME, FastPathKind::WireData),
        6 => (RecordType::SOA, FastPathKind::WireData),
        12 => (RecordType::PTR, FastPathKind::WireData),
        15 => (RecordType::MX, FastPathKind::WireData),
        16 => (RecordType::TXT, FastPathKind::WireData),
        28 => (RecordType::AAAA, FastPathKind::IpAddress),
        33 => (RecordType::SRV, FastPathKind::WireData),
        64 => (RecordType::SVCB, FastPathKind::WireData),
        65 => (RecordType::HTTPS, FastPathKind::WireData),
        _ => return None,
    };

    let question_end = pos;
    let mut client_max_size: u16 = 512;
    let mut wants_dnssec = false;
    let mut opt = None;

    if arcount > 0 {
        let mut ar_pos = question_end;
        for _ in 0..arcount {
            if ar_pos >= buf.len() {
                break;
            }
            if buf[ar_pos] != 0x00 {
                return None;
            }
            ar_pos += 1;

            if ar_pos + 9 > buf.len() {
                return None;
            }

            let rr_type = u16::from_be_bytes([buf[ar_pos], buf[ar_pos + 1]]);
            ar_pos += 2;

            if rr_type == 41 {
                // RFC 6891 §6.1.1: a second OPT is a FORMERR; hickory rejects it too.
                if opt.is_some() {
                    return None;
                }
                let udp_size = u16::from_be_bytes([buf[ar_pos], buf[ar_pos + 1]]);
                client_max_size = udp_size.max(512);
                ar_pos += 2;

                if ar_pos + 4 > buf.len() {
                    return None;
                }
                if !is_valid_edns_version(buf[ar_pos + 1]) {
                    return None;
                }
                let do_flags = u16::from_be_bytes([buf[ar_pos + 2], buf[ar_pos + 3]]);
                wants_dnssec = do_flags & 0x8000 != 0;
                ar_pos += 4;

                if ar_pos + 2 > buf.len() {
                    return None;
                }
                let rdlen = u16::from_be_bytes([buf[ar_pos], buf[ar_pos + 1]]) as usize;
                opt = Some(parse_opt_options(buf, ar_pos + 2, rdlen)?);
                ar_pos += 2 + rdlen;
            } else {
                ar_pos += 2;
                ar_pos += 4;
                if ar_pos + 2 > buf.len() {
                    return None;
                }
                let rdlen = u16::from_be_bytes([buf[ar_pos], buf[ar_pos + 1]]) as usize;
                ar_pos += 2 + rdlen;
            }
        }
    }

    Some(FastPathQuery {
        id,
        record_type,
        kind,
        question_end,
        client_max_size,
        wants_dnssec,
        recursion_desired: flags & 0x0100 != 0,
        checking_disabled: flags & 0x0010 != 0,
        opt,
        domain_buf,
        domain_len,
    })
}

fn is_valid_edns_version(version_byte: u8) -> bool {
    version_byte == 0
}
