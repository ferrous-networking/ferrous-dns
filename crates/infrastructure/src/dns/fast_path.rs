use ferrous_dns_domain::RecordType;

const MAX_DOMAIN_LEN: usize = 253;

/// Distinguishes A/AAAA queries (served inline via `build_cache_hit_response`)
/// from other record types whose cached form is raw wire data.
pub enum FastPathKind {
    /// A (1) or AAAA (28) — address records, served inline without heap alloc.
    IpAddress,
    /// NS (2), CNAME (5), SOA (6), PTR (12), MX (15), TXT (16), HTTPS (65),
    /// SRV (33), SVCB (64) — cached as `CachedData::WireData`; served by
    /// patching the query ID in the raw bytes.
    WireData,
}

pub struct FastPathQuery {
    pub id: u16,
    pub record_type: RecordType,
    /// How this query's cache hit should be served.
    pub kind: FastPathKind,
    pub question_end: usize,
    pub client_max_size: u16,
    pub has_edns: bool,
    /// The client set the EDNS DO bit — it is DNSSEC-aware and expects the AD
    /// bit / validation to be honoured. Such queries skip the inline cache fast
    /// path (which cannot set AD) and take the full resolver path instead.
    pub wants_dnssec: bool,
    domain_buf: [u8; MAX_DOMAIN_LEN + 1],
    domain_len: usize,
}

impl FastPathQuery {
    pub fn domain(&self) -> &str {
        core::str::from_utf8(&self.domain_buf[..self.domain_len]).unwrap_or_default()
    }
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
        for &b in &buf[pos..pos + label_len] {
            // A label byte that hickory would escape (`.`, `\`, anything not
            // printable ASCII) must not be copied verbatim: `domain_buf` is
            // flattened with `.` separators into the cache key, so a literal
            // dot inside a label collides with the multi-label name that reads
            // the same, and a non-UTF-8 byte makes `domain()` fall back to the
            // empty string. The slow path parses such names with hickory,
            // which escapes them, so hand the packet over instead.
            if b == b'.' || b == b'\\' || !b.is_ascii_graphic() {
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
    let mut has_edns = false;
    let mut wants_dnssec = false;

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
                has_edns = true;
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
        has_edns,
        wants_dnssec,
        domain_buf,
        domain_len,
    })
}

fn is_valid_edns_version(version_byte: u8) -> bool {
    version_byte == 0
}
