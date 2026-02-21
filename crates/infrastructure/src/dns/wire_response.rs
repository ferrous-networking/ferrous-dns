use super::fast_path::FastPathQuery;
use std::net::IpAddr;

const OPT_RECORD: [u8; 11] = [
    0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Builds a DNS A/AAAA response directly in wire format using a stack-allocated
/// buffer — no heap allocation, no Hickory serialization path.
///
/// Returns `(buffer, length)` on success.
/// Returns `None` when the response would exceed the client's advertised UDP
/// payload size (from EDNS0 OPT) or the hard 512-byte fallback cap.
///
/// When the client sent an EDNS0 OPT record (`query.has_edns`), an OPT record
/// is appended to the additional section per RFC 6891 §6.1.1.
pub fn build_cache_hit_response(
    query: &FastPathQuery,
    query_buf: &[u8],
    addresses: &[IpAddr],
    ttl: u32,
) -> Option<([u8; 523], usize)> {
    if addresses.is_empty() || query.question_end > query_buf.len() {
        return None;
    }

    let question_len = query.question_end - 12;

    let answers_size: usize = addresses
        .iter()
        .map(|a| match a {
            IpAddr::V4(_) => 16,
            IpAddr::V6(_) => 28,
        })
        .sum();

    let opt_size = if query.has_edns { OPT_RECORD.len() } else { 0 };
    let total_size = 12 + question_len + answers_size + opt_size;
    let max_size = (query.client_max_size as usize).min(512) + opt_size;

    if total_size > max_size {
        return None;
    }

    let mut buf = [0u8; 523];

    buf[0] = (query.id >> 8) as u8;
    buf[1] = query.id as u8;
    buf[2] = 0x81;
    buf[3] = 0x80;
    buf[4] = 0x00;
    buf[5] = 0x01;
    let ancount = addresses.len() as u16;
    buf[6] = (ancount >> 8) as u8;
    buf[7] = ancount as u8;
    buf[10] = 0x00;
    buf[11] = if query.has_edns { 0x01 } else { 0x00 };

    buf[12..12 + question_len].copy_from_slice(&query_buf[12..query.question_end]);

    let mut pos = 12 + question_len;

    for addr in addresses {
        buf[pos] = 0xC0;
        buf[pos + 1] = 0x0C;

        match addr {
            IpAddr::V4(ipv4) => {
                buf[pos + 2] = 0x00;
                buf[pos + 3] = 0x01;
                buf[pos + 4] = 0x00;
                buf[pos + 5] = 0x01;
                buf[pos + 6] = (ttl >> 24) as u8;
                buf[pos + 7] = (ttl >> 16) as u8;
                buf[pos + 8] = (ttl >> 8) as u8;
                buf[pos + 9] = ttl as u8;
                buf[pos + 10] = 0x00;
                buf[pos + 11] = 0x04;
                buf[pos + 12..pos + 16].copy_from_slice(&ipv4.octets());
                pos += 16;
            }
            IpAddr::V6(ipv6) => {
                buf[pos + 2] = 0x00;
                buf[pos + 3] = 0x1C;
                buf[pos + 4] = 0x00;
                buf[pos + 5] = 0x01;
                buf[pos + 6] = (ttl >> 24) as u8;
                buf[pos + 7] = (ttl >> 16) as u8;
                buf[pos + 8] = (ttl >> 8) as u8;
                buf[pos + 9] = ttl as u8;
                buf[pos + 10] = 0x00;
                buf[pos + 11] = 0x10;
                buf[pos + 12..pos + 28].copy_from_slice(&ipv6.octets());
                pos += 28;
            }
        }
    }

    if query.has_edns {
        buf[pos..pos + OPT_RECORD.len()].copy_from_slice(&OPT_RECORD);
        pos += OPT_RECORD.len();
    }

    Some((buf, pos))
}
