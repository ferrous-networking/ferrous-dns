use super::fast_path::FastPathQuery;
use std::net::IpAddr;

/// Builds a DNS A/AAAA response directly in wire format using a stack-allocated
/// 512-byte buffer — no heap allocation, no Hickory serialization path.
///
/// Returns `(buffer, length)` on success.
/// Returns `None` when the response would exceed the client's advertised UDP
/// payload size (from EDNS0 OPT) or the hard 512-byte fallback cap.
pub fn build_cache_hit_response(
    query: &FastPathQuery,
    query_buf: &[u8],
    addresses: &[IpAddr],
    ttl: u32,
) -> Option<([u8; 512], usize)> {
    if addresses.is_empty() || query.question_end > query_buf.len() {
        return None;
    }

    let question_len = query.question_end - 12;

    // Answer wire sizes: NAME(2)+TYPE(2)+CLASS(2)+TTL(4)+RDLEN(2)+RDATA
    let answers_size: usize = addresses
        .iter()
        .map(|a| match a {
            IpAddr::V4(_) => 16, // RDATA = 4 bytes
            IpAddr::V6(_) => 28, // RDATA = 16 bytes
        })
        .sum();

    let total_size = 12 + question_len + answers_size;
    let max_size = (query.client_max_size as usize).min(512);

    if total_size > max_size {
        return None;
    }

    let mut buf = [0u8; 512];

    // ── Header (12 bytes) ────────────────────────────────────────────────────
    buf[0] = (query.id >> 8) as u8;
    buf[1] = query.id as u8;
    buf[2] = 0x81; // QR=1 OPCODE=0 AA=0 TC=0 RD=1
    buf[3] = 0x80; // RA=1 Z=0 AD=0 CD=0 RCODE=0 (NoError)
    buf[4] = 0x00;
    buf[5] = 0x01; // QDCOUNT = 1
    let ancount = addresses.len() as u16;
    buf[6] = (ancount >> 8) as u8;
    buf[7] = ancount as u8;
    // NSCOUNT and ARCOUNT remain 0x0000

    // ── Question section — copied verbatim from the client query ─────────────
    buf[12..12 + question_len].copy_from_slice(&query_buf[12..query.question_end]);

    let mut pos = 12 + question_len;

    // ── Answer records ───────────────────────────────────────────────────────
    for addr in addresses {
        // NAME: compression pointer to byte offset 12 (start of QNAME)
        buf[pos] = 0xC0;
        buf[pos + 1] = 0x0C;

        match addr {
            IpAddr::V4(ipv4) => {
                buf[pos + 2] = 0x00; // TYPE A = 1
                buf[pos + 3] = 0x01;
                buf[pos + 4] = 0x00; // CLASS IN = 1
                buf[pos + 5] = 0x01;
                buf[pos + 6] = (ttl >> 24) as u8;
                buf[pos + 7] = (ttl >> 16) as u8;
                buf[pos + 8] = (ttl >> 8) as u8;
                buf[pos + 9] = ttl as u8;
                buf[pos + 10] = 0x00;
                buf[pos + 11] = 0x04; // RDLEN = 4
                buf[pos + 12..pos + 16].copy_from_slice(&ipv4.octets());
                pos += 16;
            }
            IpAddr::V6(ipv6) => {
                buf[pos + 2] = 0x00; // TYPE AAAA = 28 (0x001C)
                buf[pos + 3] = 0x1C;
                buf[pos + 4] = 0x00; // CLASS IN = 1
                buf[pos + 5] = 0x01;
                buf[pos + 6] = (ttl >> 24) as u8;
                buf[pos + 7] = (ttl >> 16) as u8;
                buf[pos + 8] = (ttl >> 8) as u8;
                buf[pos + 9] = ttl as u8;
                buf[pos + 10] = 0x00;
                buf[pos + 11] = 0x10; // RDLEN = 16
                buf[pos + 12..pos + 28].copy_from_slice(&ipv6.octets());
                pos += 28;
            }
        }
    }

    Some((buf, pos))
}
