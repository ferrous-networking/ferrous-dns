use ferrous_dns_domain::RecordType;

const MAX_DOMAIN_LEN: usize = 253;

/// Result of a successful fast-path parse of a raw DNS query buffer.
pub struct FastPathQuery {
    pub id: u16,
    pub record_type: RecordType,
    /// Byte offset in the original buffer where the question section ends.
    pub question_end: usize,
    /// Maximum UDP payload size advertised by the client via EDNS0 (capped at 512).
    pub client_max_size: u16,
    /// True when the client sent an EDNS0 OPT record (RFC 6891 §6.1.1: the
    /// server SHOULD include an OPT record in the response when this is true).
    pub has_edns: bool,
    domain_buf: [u8; MAX_DOMAIN_LEN + 1],
    domain_len: usize,
}

impl FastPathQuery {
    /// Returns the decoded domain name (e.g. `"google.com"`, no trailing dot).
    pub fn domain(&self) -> &str {
        core::str::from_utf8(&self.domain_buf[..self.domain_len]).unwrap_or_default()
    }
}

/// Attempts a minimal parse of a raw DNS query buffer.
///
/// Returns `None` — and therefore falls back to the full Hickory pipeline — for
/// any packet that is not a plain A/AAAA query in the IN class:
///
/// * Buffer shorter than 17 bytes
/// * QR bit set (response, not query)
/// * Non-zero OPCODE (not a standard QUERY)
/// * QDCOUNT ≠ 1, ANCOUNT ≠ 0, or NSCOUNT ≠ 0
/// * Compression pointer or extended label type in the QNAME
/// * QTYPE other than A (1) or AAAA (28)
/// * QCLASS other than IN (1)
/// * DNSSEC OK bit set in an EDNS0 OPT record
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
        for &b in &buf[pos..pos + label_len] {
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

    let record_type = match qtype {
        1 => RecordType::A,
        28 => RecordType::AAAA,
        _ => return None,
    };

    let question_end = pos;
    let mut client_max_size: u16 = 512;
    let mut has_edns = false;

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
                ar_pos += 4;

                if do_flags & 0x8000 != 0 {
                    return None;
                }

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
        question_end,
        client_max_size,
        has_edns,
        domain_buf,
        domain_len,
    })
}

fn is_valid_edns_version(version_byte: u8) -> bool {
    version_byte == 0
}
