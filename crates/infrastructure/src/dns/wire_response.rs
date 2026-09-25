use super::cache::storage::STALE_SERVE_TTL;
use super::ede::{self, ExtendedDnsError};
use super::fast_path::FastPathQuery;
use std::net::IpAddr;
use std::ops::RangeInclusive;

/// The fast path's fixed OPT: `EdnsReply` with DO clear and no options, as a
/// constant so a cache hit copies it instead of encoding it.
const OPT_RECORD: [u8; 11] = [
    0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

/// Capacity of the fixed fast-path cache-hit response buffer. A hit that would
/// exceed it is rejected (`None`) and handled by the slow path instead.
pub const RESPONSE_BUF_LEN: usize = 523;

/// Rewrites a relayed response's header for the client: its ID, its RD bit
/// (RFC 1035 §4.1.1 copies RD from the query; upstream always saw RD=1) and
/// our own AD verdict (RFC 4035 bit `0x20` of byte 3). No-op on a buffer
/// shorter than the flags.
pub fn set_relay_header(buf: &mut [u8], id: u16, recursion_desired: bool, authentic_data: bool) {
    let Some([id_hi, id_lo, flags_hi, flags_lo]) = buf.first_chunk_mut::<4>() else {
        return;
    };
    [*id_hi, *id_lo] = id.to_be_bytes();
    *flags_hi = (*flags_hi & !0x01) | u8::from(recursion_desired);
    *flags_lo = (*flags_lo & !0x20) | (u8::from(authentic_data) << 5);
}

/// Over UDP a cached wire answer larger than the client's advertised EDNS
/// buffer (or 512 without EDNS) must be deferred to the slow path, which
/// truncates it with TC=1 (RFC 6891 §6.2.5 / RFC 7766). Returns `true` when the
/// `wire_len` bytes fit and may be served verbatim on the fast path.
pub fn wire_fits_udp_buffer(wire_len: usize, client_max_size: u16) -> bool {
    wire_len <= client_max_size as usize
}

/// Encodes a cache hit into `out`, which may hold a previous response, and
/// returns its length. `None` if it would not fit the client or `out`.
pub fn build_cache_hit_response(
    query: &FastPathQuery,
    query_buf: &[u8],
    addresses: &[IpAddr],
    ttl: u32,
    out: &mut [u8; RESPONSE_BUF_LEN],
) -> Option<usize> {
    if addresses.is_empty() || query.question_end > query_buf.len() {
        return None;
    }

    let question_len = query.question_end - 12;

    let answers_size: usize = addresses.iter().map(address_rr_len).sum();

    let opt_size = if query.has_edns() {
        OPT_RECORD.len()
    } else {
        0
    };
    let total_size = 12 + question_len + answers_size + opt_size;
    let max_size = query.client_max_size as usize;

    // `max_size` is the client's EDNS-advertised buffer (up to 65535), so the
    // size check alone does NOT bound `total_size` to our fixed buffer. Without
    // the `RESPONSE_BUF_LEN` guard a large cached RRset (~32 A or ~18 AAAA
    // records for one name) overflows the slice writes below and panics the
    // worker; reject it here so the slow path serves it instead.
    if total_size > max_size || total_size > RESPONSE_BUF_LEN {
        return None;
    }

    let ancount = addresses.len() as u16;
    // Every byte of `out[..total_size]` is written: `out` is reused, not zeroed.
    out[0..2].copy_from_slice(&query.id.to_be_bytes());
    out[2..4].copy_from_slice(&[0x81, 0x80]);
    out[4..6].copy_from_slice(&1u16.to_be_bytes());
    out[6..8].copy_from_slice(&ancount.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&u16::from(query.has_edns()).to_be_bytes());

    out[12..12 + question_len].copy_from_slice(&query_buf[12..query.question_end]);

    let mut pos = 12 + question_len;

    for addr in addresses {
        pos += write_address_rr(&mut out[pos..], addr, ttl);
    }

    if query.has_edns() {
        out[pos..pos + OPT_RECORD.len()].copy_from_slice(&OPT_RECORD);
        pos += OPT_RECORD.len();
    }

    Some(pos)
}

/// Answer-section size of one A (16) or AAAA (28) record owned by `C0 0C`.
#[inline]
fn address_rr_len(addr: &IpAddr) -> usize {
    match addr {
        IpAddr::V4(_) => 16,
        IpAddr::V6(_) => 28,
    }
}

/// Writes one A/AAAA record whose owner is a pointer to the first question
/// name (offset 12) at the start of `out`; returns its length.
#[inline]
fn write_address_rr(out: &mut [u8], addr: &IpAddr, ttl: u32) -> usize {
    let (rtype, rdlen): (u16, u16) = match addr {
        IpAddr::V4(_) => (1, 4),
        IpAddr::V6(_) => (28, 16),
    };
    out[0..2].copy_from_slice(&[0xC0, 0x0C]);
    out[2..4].copy_from_slice(&rtype.to_be_bytes());
    out[4..6].copy_from_slice(&CLASS_IN.to_be_bytes());
    out[6..10].copy_from_slice(&ttl.to_be_bytes());
    out[10..12].copy_from_slice(&rdlen.to_be_bytes());
    match addr {
        IpAddr::V4(v4) => out[12..16].copy_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out[12..28].copy_from_slice(&v6.octets()),
    }
    12 + usize::from(rdlen)
}

const CLASS_IN: u16 = 1;
const TYPE_SOA: u16 = 6;
const TYPE_SIG: u16 = 24;
const TYPE_OPT: u16 = 41;
const TYPE_RRSIG: u16 = 46;
const TYPE_NSEC: u16 = 47;
const TYPE_NSEC3: u16 = 50;
const TYPE_ANY: u16 = 255;
const TYPE_TSIG: u16 = 250;
/// EDNS option code of the DNS Cookie (RFC 7873 §4).
pub(crate) const COOKIE_OPTION_CODE: u16 = 10;
/// UDP payload size advertised in every OPT this server writes.
const EDNS_UDP_PAYLOAD: u16 = 4096;
/// `hostmaster.ferrous-dns.invalid.` — the synthetic SOA RNAME.
const SOA_RNAME: &[u8] = b"\x0ahostmaster\x0bferrous-dns\x07invalid\x00";

/// Response codes this server sets in the header (RFC 1035 §4.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rcode {
    NoError = 0,
    FormErr = 1,
    ServFail = 2,
    NxDomain = 3,
    Refused = 5,
}

/// Header fields of a response that are not derived from its sections.
#[derive(Debug, Clone, Copy)]
pub struct ResponseHead {
    pub id: u16,
    pub recursion_desired: bool,
    pub authentic_data: bool,
    pub rcode: Rcode,
}

impl ResponseHead {
    fn flags(&self, truncated: bool) -> [u8; 2] {
        let mut hi = 0x80 | u8::from(self.recursion_desired);
        if truncated {
            hi |= 0x02;
        }
        // RA is always set: this server recurses for every client.
        let lo = 0x80 | (u8::from(self.authentic_data) << 5) | self.rcode as u8;
        [hi, lo]
    }
}

/// The response OPT record. Callers pass one iff the query carried OPT —
/// RFC 6891 §7 forbids an OPT in the reply to a query without one.
#[derive(Debug, Clone, Copy)]
pub struct EdnsReply<'a> {
    /// RFC 3225 §3: the DO bit is copied from the query.
    pub dnssec_ok: bool,
    /// Full COOKIE option payload: client cookie followed by server cookie.
    pub cookie: Option<&'a [u8]>,
    pub ede: Option<&'a ExtendedDnsError>,
}

impl EdnsReply<'_> {
    /// Bytes [`Self::write`] appends.
    fn len(&self) -> usize {
        OPT_RECORD.len() + self.rdata_len()
    }

    fn rdata_len(&self) -> usize {
        self.cookie.map_or(0, |c| 4 + c.len()) + self.ede.map_or(0, |e| 6 + e.extra_text.len())
    }

    /// Appends the OPT, whose TTL opens with `extended_rcode`, the upper
    /// eight RCODE bits (RFC 6891 §6.1.3).
    fn write(&self, out: &mut Vec<u8>, extended_rcode: u8) {
        out.extend_from_slice(&opt_head(
            extended_rcode,
            self.dnssec_ok,
            self.rdata_len() as u16,
        ));
        if let Some(cookie) = self.cookie {
            out.extend_from_slice(&COOKIE_OPTION_CODE.to_be_bytes());
            out.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
            out.extend_from_slice(cookie);
        }
        if let Some(ede) = self.ede {
            let text = ede.extra_text.as_bytes();
            out.extend_from_slice(&ede::OPTION_CODE.to_be_bytes());
            out.extend_from_slice(&((2 + text.len()) as u16).to_be_bytes());
            out.extend_from_slice(&ede.info_code.to_be_bytes());
            out.extend_from_slice(text);
        }
    }
}

/// What follows the question section.
#[derive(Debug, Clone, Copy)]
pub enum ResponseBody<'a> {
    Empty,
    /// A/AAAA answers owned by the first question name.
    Addresses {
        addresses: &'a [IpAddr],
        ttl: u32,
    },
    /// No answer, plus a synthetic SOA in authority so resolvers can cache the
    /// negative answer for `ttl` (RFC 2308).
    NegativeSoa {
        ttl: u32,
    },
}

/// Encodes a response echoing `question` — `qdcount` wire-format questions
/// whose first name is uncompressed, so `C0 0C` addresses it.
pub fn encode_response(
    head: &ResponseHead,
    question: &[u8],
    qdcount: u16,
    body: ResponseBody<'_>,
    edns: Option<&EdnsReply<'_>>,
) -> Vec<u8> {
    let (ancount, nscount, body_len) = match body {
        ResponseBody::Empty => (0, 0, 0),
        ResponseBody::Addresses { addresses, .. } => (
            addresses.len() as u16,
            0,
            addresses.iter().map(address_rr_len).sum(),
        ),
        ResponseBody::NegativeSoa { .. } => (0, 1, 12 + 2 + SOA_RNAME.len() + 20),
    };
    let mut out = Vec::with_capacity(12 + question.len() + body_len + 64);
    write_header(
        &mut out,
        head.id,
        head.flags(false),
        qdcount,
        ancount,
        nscount,
        u16::from(edns.is_some()),
    );
    out.extend_from_slice(question);
    match body {
        ResponseBody::Empty => {}
        ResponseBody::Addresses { addresses, ttl } => {
            for addr in addresses {
                let mut rr = [0u8; 28];
                let len = write_address_rr(&mut rr, addr, ttl);
                out.extend_from_slice(&rr[..len]);
            }
        }
        ResponseBody::NegativeSoa { ttl } => {
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(&TYPE_SOA.to_be_bytes());
            out.extend_from_slice(&CLASS_IN.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&((2 + SOA_RNAME.len() + 20) as u16).to_be_bytes());
            // MNAME is the queried name itself; resolvers key the negative
            // cache off MINIMUM, so an exact zone apex is not required.
            out.extend_from_slice(&[0xC0, 0x0C]);
            out.extend_from_slice(SOA_RNAME);
            for field in [1u32, 3600, 600, 604_800, ttl] {
                out.extend_from_slice(&field.to_be_bytes());
            }
        }
    }
    if let Some(edns) = edns {
        edns.write(&mut out, 0);
    }
    out
}

/// Header plus question with TC=1: tells a UDP client to retry over TCP.
pub fn encode_truncated(
    id: u16,
    recursion_desired: bool,
    question: &[u8],
    qdcount: u16,
) -> Vec<u8> {
    let head = ResponseHead {
        id,
        recursion_desired,
        authentic_data: false,
        rcode: Rcode::NoError,
    };
    let mut out = Vec::with_capacity(12 + question.len());
    write_header(&mut out, id, head.flags(true), qdcount, 0, 0, 0);
    out.extend_from_slice(question);
    out
}

fn write_header(out: &mut Vec<u8>, id: u16, flags: [u8; 2], qd: u16, an: u16, ns: u16, ar: u16) {
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags);
    for count in [qd, an, ns, ar] {
        out.extend_from_slice(&count.to_be_bytes());
    }
}

/// Re-issues an upstream response under the client's header and OPT: ID and
/// RD from the client, AD as given, the upstream OPT and any transaction
/// signature dropped and `edns` appended in their place, carrying the
/// upstream's extended RCODE bits. A client without DO (no `edns`, or
/// `dnssec_ok` clear) gets no authenticating DNSSEC RRs it did not ask for
/// (RFC 4035 §3.2.1). `None` if `upstream` is
/// not a well-formed sequence of sections, holds two OPTs or an OPT outside
/// the additional section, or has an extended RCODE that `edns: None` cannot
/// carry.
pub fn relay_with_edns(
    upstream: &[u8],
    id: u16,
    recursion_desired: bool,
    authentic_data: bool,
    edns: Option<&EdnsReply<'_>>,
) -> Option<Vec<u8>> {
    let strip = !edns.is_some_and(|e| e.dnssec_ok);
    let sections = resection(upstream, strip)?;
    let mut out = append_opt(sections.out, sections.extended_rcode, edns)?;
    set_relay_header(&mut out, id, recursion_desired, authentic_data);
    Some(out)
}

/// EDNS option code, from the local and experimental range (RFC 6891 §9), of
/// the option in the OPT of the cache form.
const CACHE_OPTION_CODE: u16 = 65_001;
/// Bytes of the cache form's OPT before its TTL offsets: the record's fixed
/// part, then the option's code, its length and the entry TTL.
const CACHE_OPT_HEAD: usize = OPT_RECORD.len() + 4 + 4;

/// Re-sections an upstream response into the form the cache stores for an
/// entry of `entry_ttl` seconds: every record but the OPT and any transaction
/// signature, its TTL clamped into `ttls`, then an OPT of ours holding the
/// upstream's extended RCODE, with DO set iff the message carries
/// authenticating DNSSEC RRs. That OPT's
/// one option carries `entry_ttl`, then the offset of every record's TTL
/// field and, last, their count. It is what lets [`relay_cached`] answer a
/// client without walking the message. The upstream's options, among them
/// the COOKIE it echoed back to us, are not kept. The header is the
/// upstream's but for ARCOUNT. `None` where [`relay_with_edns`] would be, for
/// a message too long to address its TTLs in 16 bits, or for one where a name
/// reads the bytes of a TTL field ([`names_read_ttls`]).
pub fn cache_form(upstream: &[u8], entry_ttl: u32, ttls: RangeInclusive<u32>) -> Option<Vec<u8>> {
    let Sections {
        mut out,
        extended_rcode,
        authenticating,
    } = resection(upstream, false)?;
    let offsets = cacheable_ttl_offsets(&mut out)?;
    for &at in &offsets {
        let ttl: &mut [u8; 4] = out.get_mut(at..at + 4)?.try_into().ok()?;
        *ttl = u32::from_be_bytes(*ttl)
            .clamp(*ttls.start(), *ttls.end())
            .to_be_bytes();
    }
    let count = u16::try_from(offsets.len()).ok()?;
    let option_len = u16::try_from(4 + 2 * offsets.len() + 2).ok()?;
    out.extend_from_slice(&opt_head(
        extended_rcode,
        authenticating,
        option_len.checked_add(4)?,
    ));
    out.extend_from_slice(&CACHE_OPTION_CODE.to_be_bytes());
    out.extend_from_slice(&option_len.to_be_bytes());
    out.extend_from_slice(&entry_ttl.to_be_bytes());
    for at in offsets {
        out.extend_from_slice(&u16::try_from(at).ok()?.to_be_bytes());
    }
    out.extend_from_slice(&count.to_be_bytes());
    let arcount = u16::from_be_bytes([out[10], out[11]]).checked_add(1)?;
    out[10..12].copy_from_slice(&arcount.to_be_bytes());
    Some(out)
}

/// Relays the cached answer `wire` (see [`cache_form`]) to a client, under
/// its ID and RD and `edns` as its OPT, every TTL counted down by
/// [`aged_ttl`] for an entry with `remaining` seconds left. AD is clear: the
/// fast path serves clients without DO, which must not see the validating
/// upstream's AD (RFC 6840 §5.8). The records are copied as they sit, and
/// re-sectioned only for a client without DO that must not see the
/// authenticating DNSSEC RRs among them. `None` for bytes not in cache form,
/// or an extended RCODE `edns: None` cannot carry.
pub fn relay_cached(
    wire: &[u8],
    id: u16,
    recursion_desired: bool,
    edns: Option<&EdnsReply<'_>>,
    remaining: u32,
) -> Option<Vec<u8>> {
    let (body, opt) = cached_opt(wire)?;
    if opt.authenticating && !edns.is_some_and(|e| e.dnssec_ok) {
        return relay_aged(wire, id, recursion_desired, false, edns, remaining);
    }
    let mut out = match edns {
        // The cache's OPT but for its option and DO, which is the query's.
        Some(&EdnsReply {
            dnssec_ok,
            cookie: None,
            ede: None,
        }) => {
            let mut out = wire.get(..body.len() + OPT_RECORD.len())?.to_vec();
            let [.., flags, _, rdlen_hi, rdlen_lo] = &mut out[..] else {
                return None;
            };
            *flags = u8::from(dnssec_ok) << 7;
            [*rdlen_hi, *rdlen_lo] = [0, 0];
            out
        }
        // In place of the cache's OPT, so ARCOUNT stands.
        Some(edns) => {
            let mut out = Vec::with_capacity(body.len() + edns.len());
            out.extend_from_slice(body);
            edns.write(&mut out, opt.extended_rcode);
            out
        }
        None if opt.extended_rcode != 0 => return None,
        None => {
            let mut out = body.to_vec();
            let arcount = u16::from_be_bytes([out[10], out[11]]).checked_sub(1)?;
            out[10..12].copy_from_slice(&arcount.to_be_bytes());
            out
        }
    };
    age_ttls(&mut out, opt.ttls, opt.entry_ttl, remaining)?;
    set_relay_header(&mut out, id, recursion_desired, false);
    Some(out)
}

/// [`relay_with_edns`] for an answer from the cache, which has `remaining`
/// seconds left: when `wire` is in cache form, [`aged_ttl`] counts down every
/// TTL of the reply.
pub fn relay_aged(
    wire: &[u8],
    id: u16,
    recursion_desired: bool,
    authentic_data: bool,
    edns: Option<&EdnsReply<'_>>,
    remaining: u32,
) -> Option<Vec<u8>> {
    let mut out = relay_with_edns(wire, id, recursion_desired, authentic_data, edns)?;
    if let Some((_, opt)) = cached_opt(wire) {
        for_each_ttl(&mut out, |ttl, _| {
            *ttl = aged_ttl(u32::from_be_bytes(*ttl), opt.entry_ttl, remaining).to_be_bytes();
        })?;
    }
    Some(out)
}
/// Counts down, by [`aged_ttl`], the TTL fields of `msg` at the big-endian
/// 16-bit offsets in `offsets`. `None` if one lies outside `msg`.
#[inline]
fn age_ttls(msg: &mut [u8], offsets: &[u8], entry_ttl: u32, remaining: u32) -> Option<()> {
    for &at in offsets.as_chunks::<2>().0 {
        let at = usize::from(u16::from_be_bytes(at));
        let ttl: &mut [u8; 4] = msg.get_mut(at..at + 4)?.try_into().ok()?;
        *ttl = aged_ttl(u32::from_be_bytes(*ttl), entry_ttl, remaining).to_be_bytes();
    }
    Some(())
}

/// The TTL a hit gives a record stored with `ttl` in an entry cached for
/// `entry_ttl` seconds, `remaining` of which are left: `ttl` less the entry's
/// age, and no more than the entry has left, as the A/AAAA hits answer. A
/// record past its own TTL is served stale, which RFC 8767 §4 answers with a
/// TTL above 0: [`STALE_SERVE_TTL`], the one a stale entry reports, or
/// `remaining` if lower.
#[inline]
fn aged_ttl(ttl: u32, entry_ttl: u32, remaining: u32) -> u32 {
    remaining
        .saturating_sub(entry_ttl.saturating_sub(ttl))
        .max(remaining.min(STALE_SERVE_TTL))
}

/// The OPT that ends a cached answer, as [`cache_form`] wrote it.
#[derive(Clone, Copy)]
struct CachedOpt<'a> {
    extended_rcode: u8,
    /// The DO bit: the message carries authenticating DNSSEC RRs.
    authenticating: bool,
    entry_ttl: u32,
    /// The big-endian 16-bit offset of every record's TTL field.
    ttls: &'a [u8],
}

/// Splits the OPT that ends the cache form `wire` from the header and records
/// before it.
#[inline]
fn cached_opt(wire: &[u8]) -> Option<(&[u8], CachedOpt<'_>)> {
    let (rest, &count) = wire.split_last_chunk::<2>()?;
    let ttls_len = 2 * usize::from(u16::from_be_bytes(count));
    let (body, opt) = rest.split_at(rest.len().checked_sub(CACHE_OPT_HEAD + ttls_len)?);
    let (&head, ttls) = opt.split_first_chunk::<CACHE_OPT_HEAD>()?;
    // Root owner, TYPE 41, CLASS, TTL (extended RCODE, version 0, flags),
    // RDLENGTH, then our option's code, its length and the entry TTL.
    let [0, 0, 41, _, _, extended_rcode, 0, flags, _, rd0, rd1, c0, c1, l0, l1, t0, t1, t2, t3] =
        head
    else {
        return None;
    };
    let option_len = 4 + ttls_len + 2;
    let well_formed = u16::from_be_bytes([c0, c1]) == CACHE_OPTION_CODE
        && usize::from(u16::from_be_bytes([l0, l1])) == option_len
        && usize::from(u16::from_be_bytes([rd0, rd1])) == 4 + option_len
        && body.len() >= 12;
    let opt = CachedOpt {
        extended_rcode,
        authenticating: flags & 0x80 != 0,
        entry_ttl: u32::from_be_bytes([t0, t1, t2, t3]),
        ttls,
    };
    well_formed.then_some((body, opt))
}

/// Calls `f` with the TTL field, and its offset, of every record of `msg`
/// but OPT. `None` if its sections do not walk.
fn for_each_ttl(msg: &mut [u8], mut f: impl FnMut(&mut [u8; 4], usize)) -> Option<()> {
    let header = msg.get(..12)?;
    let count = |i: usize| usize::from(u16::from_be_bytes([header[i], header[i + 1]]));
    let (questions, records) = (count(4), count(6) + count(8) + count(10));
    let mut pos = 12;
    for _ in 0..questions {
        pos = skip_name(msg, pos)? + 4;
    }
    for _ in 0..records {
        let fixed = skip_name(msg, pos)?;
        let [t0, t1, _, _, ttl @ .., l0, l1] = msg.get_mut(fixed..)?.first_chunk_mut::<10>()?;
        if u16::from_be_bytes([*t0, *t1]) != TYPE_OPT {
            f(ttl, fixed + 4);
        }
        pos = fixed + 10 + usize::from(u16::from_be_bytes([*l0, *l1]));
    }
    (pos <= msg.len()).then_some(())
}

/// Whether decoding a name of `msg` reads a byte of a TTL field, at the
/// ascending `ttls` offsets. Only a pointer RFC 1035 §4.1.4 forbids gets
/// there, and such a name would change as the cache clamps and counts down
/// the TTLs it runs through. `None` if the sections do not walk.
fn names_read_ttls(msg: &[u8], ttls: &[usize]) -> Option<bool> {
    let header = msg.get(..12)?;
    let count = |i: usize| usize::from(u16::from_be_bytes([header[i], header[i + 1]]));
    let reads_ttl = |from: usize, to: usize| {
        let i = ttls.partition_point(|&at| at + 4 <= from);
        ttls.get(i).is_some_and(|&at| at < to)
    };
    let mut read = false;
    let mut pos = 12;
    for _ in 0..count(4) {
        pos = walk_name(msg, pos, &mut |from, to| read |= reads_ttl(from, to))? + 4;
    }
    for _ in 0..count(6) + count(8) + count(10) {
        let fixed = walk_name(msg, pos, &mut |from, to| read |= reads_ttl(from, to))?;
        let f = msg.get(fixed..fixed + 10)?;
        let rtype = u16::from_be_bytes([f[0], f[1]]);
        let end = fixed + 10 + usize::from(u16::from_be_bytes([f[8], f[9]]));
        let mut at = fixed + 10;
        for field in rdata_fields(rtype) {
            at = match *field {
                Field::Fixed(len) => at + len,
                Field::Text => at + 1 + usize::from(*msg.get(at)?),
                Field::Name => walk_name(msg, at, &mut |from, to| read |= reads_ttl(from, to))?,
            };
        }
        if at > end {
            return None;
        }
        pos = end;
    }
    Some(read)
}

/// Decodes the name at `pos` as a client would, calling `read` with every
/// byte range it reads, pointers followed; returns the offset past it where
/// it is written.
fn walk_name(msg: &[u8], mut pos: usize, read: &mut impl FnMut(usize, usize)) -> Option<usize> {
    let mut end = None;
    let mut len = 0usize;
    loop {
        let byte = *msg.get(pos)?;
        match byte & 0xC0 {
            0x00 => {
                let next = pos + 1 + usize::from(byte);
                msg.get(pos..next)?;
                read(pos, next);
                len += 1 + usize::from(byte);
                if len > 255 {
                    return None;
                }
                if byte == 0 {
                    return Some(end.unwrap_or(next));
                }
                pos = next;
            }
            0xC0 => {
                read(pos, pos + 2);
                let target = usize::from(u16::from_be_bytes([byte & 0x3F, *msg.get(pos + 1)?]));
                if target >= pos {
                    return None;
                }
                end.get_or_insert(pos + 2);
                pos = target;
            }
            _ => return None,
        }
    }
}

/// The offset of every TTL field of the re-sectioned `msg`, or `None` when
/// the cache must decline it: its sections do not walk, or a name reads the
/// bytes of a TTL field ([`names_read_ttls`]).
fn cacheable_ttl_offsets(msg: &mut [u8]) -> Option<Vec<usize>> {
    let mut offsets = Vec::new();
    for_each_ttl(msg, |_, at| offsets.push(at))?;
    (!names_read_ttls(msg, &offsets)?).then_some(offsets)
}

/// Whether [`cache_form`] declines `upstream` although it re-sections, which
/// is to say for its names or TTLs alone.
#[cfg(feature = "fuzzing")]
pub(crate) fn cache_form_declines_names(upstream: &[u8]) -> bool {
    resection(upstream, false).is_some_and(|mut s| cacheable_ttl_offsets(&mut s.out).is_none())
}

/// The fixed part of an OPT record: root owner, TYPE, our UDP payload size as
/// CLASS, the TTL (extended RCODE, version 0, the flags word with DO in its
/// top bit), then RDLENGTH.
fn opt_head(extended_rcode: u8, dnssec_ok: bool, rdlen: u16) -> [u8; 11] {
    let [type_hi, type_lo] = TYPE_OPT.to_be_bytes();
    let [payload_hi, payload_lo] = EDNS_UDP_PAYLOAD.to_be_bytes();
    let [rdlen_hi, rdlen_lo] = rdlen.to_be_bytes();
    [
        0,
        type_hi,
        type_lo,
        payload_hi,
        payload_lo,
        extended_rcode,
        0,
        u8::from(dnssec_ok) << 7,
        0,
        rdlen_hi,
        rdlen_lo,
    ]
}

/// Appends `edns` to the re-sectioned records in `out`, carrying the dropped
/// OPT's extended RCODE; `None` if that RCODE is set and there is no `edns`
/// to carry it.
fn append_opt(
    mut out: Vec<u8>,
    extended_rcode: u8,
    edns: Option<&EdnsReply<'_>>,
) -> Option<Vec<u8>> {
    match edns {
        Some(edns) => {
            edns.write(&mut out, extended_rcode);
            let arcount = u16::from_be_bytes([out[10], out[11]]).checked_add(1)?;
            out[10..12].copy_from_slice(&arcount.to_be_bytes());
        }
        None if extended_rcode != 0 => return None,
        None => {}
    }
    Some(out)
}

/// Whether a client that did not set DO must not see a record of `rtype`:
/// RFC 4035 §3.2.1 strips the authenticating DNSSEC RRs, but not a type the
/// query asked for (RFC 3225 §3 counts ANY as asking).
fn is_authenticating(rtype: u16, qtype: Option<u16>) -> bool {
    matches!(rtype, TYPE_RRSIG | TYPE_NSEC | TYPE_NSEC3)
        && !qtype.is_some_and(|q| q == rtype || q == TYPE_ANY)
}

/// Whether the additional record of `rtype` at `pos`, ending at `end`, is a
/// TSIG or a SIG(0): it signs the upstream's transaction with us, whose
/// receiver removes it (RFC 8945 §5.3, RFC 2931 §3), and it must stay the
/// last record, where our OPT goes.
fn is_transaction_signature(msg: &[u8], pos: usize, end: usize, rtype: u16) -> bool {
    match rtype {
        TYPE_TSIG => true,
        // SIG(0) covers type 0, the first field of its RDATA.
        TYPE_SIG => skip_name(msg, pos)
            .and_then(|fixed| msg.get(fixed + 10..end))
            .is_some_and(|rdata| rdata.starts_with(&[0, 0])),
        _ => false,
    }
}

/// A message re-sectioned without its OPT.
struct Sections {
    /// Header and every kept record; the header's counts match them.
    out: Vec<u8>,
    /// The upper eight RCODE bits from the dropped OPT (RFC 6891 §6.1.3).
    extended_rcode: u8,
    /// The message carried authenticating DNSSEC RRs, kept or not.
    authenticating: bool,
}

/// Copies `upstream` without its OPT and transaction signature and, when
/// `strip`, without its authenticating DNSSEC RRs. See [`relay_with_edns`]
/// for `None`.
fn resection(upstream: &[u8], strip: bool) -> Option<Sections> {
    let header = upstream.get(..12)?;
    let count = |i: usize| u16::from_be_bytes([header[i], header[i + 1]]);

    let mut pos = 12;
    let mut qtype = None;
    for _ in 0..count(4) {
        pos = skip_name(upstream, pos)?;
        let fixed = upstream.get(pos..pos + 4)?;
        qtype.get_or_insert(u16::from_be_bytes([fixed[0], fixed[1]]));
        pos += 4;
    }

    let mut copy = Rewriter::new(upstream);
    let mut kept = [0u16; 3];
    let mut extended_rcode = None;
    let mut authenticating = false;
    for (section, total) in [count(6), count(8), count(10)].into_iter().enumerate() {
        for _ in 0..total {
            let (rtype, end) = skip_rr(upstream, pos)?;
            let dropped = if rtype == TYPE_OPT {
                if section != 2 || extended_rcode.is_some() {
                    return None;
                }
                // The upper eight RCODE bits open the OPT's TTL field.
                extended_rcode = Some(*upstream.get(skip_name(upstream, pos)? + 4)?);
                true
            } else if section == 2 && is_transaction_signature(upstream, pos, end, rtype) {
                true
            } else if is_authenticating(rtype, qtype) {
                authenticating = true;
                strip
            } else {
                false
            };
            if dropped {
                copy.drop_from(pos);
            } else {
                copy.keep(pos, end, rtype)?;
                kept[section] += 1;
            }
            pos = end;
        }
    }

    let mut out = copy.finish(pos);
    for (at, n) in [6, 8, 10].into_iter().zip(kept) {
        out[at..at + 2].copy_from_slice(&n.to_be_bytes());
    }
    Some(Sections {
        out,
        extended_rcode: extended_rcode.unwrap_or(0),
        authenticating,
    })
}

/// Copies the records of a message being re-sectioned. Nothing is copied
/// until the first record is dropped: the bytes before it go over in one
/// piece, at their own offsets. Past that point the records move, so each
/// kept one is copied field by field, logging every byte copied as is in
/// `spans` for the compression pointers that follow to find it.
struct Rewriter<'a> {
    src: &'a [u8],
    out: Vec<u8>,
    /// Source offset of the first dropped record.
    cut: Option<usize>,
    /// `(source start, source end, output start)` of each run copied as is
    /// past `cut`, in source order.
    spans: Vec<(usize, usize, usize)>,
}

/// A run of RDATA fields that [`Rewriter::keep`] copies.
#[derive(Clone, Copy)]
enum Field {
    Fixed(usize),
    /// A length-prefixed character string.
    Text,
    Name,
}

/// Whether re-sectioning may rewrite the names inside the RDATA of `rtype`.
#[cfg(feature = "fuzzing")]
pub(crate) fn rdata_has_names(rtype: u16) -> bool {
    !rdata_fields(rtype).is_empty()
}

/// The leading RDATA fields of `rtype` up to its last domain name: the types
/// whose names a compressor may point at or into (RFC 3597 §4), with the
/// DNSSEC and SVCB names that must not be compressed but might be. The rest
/// of the RDATA, and every other type's, is copied as is.
fn rdata_fields(rtype: u16) -> &'static [Field] {
    use Field::{Fixed, Name, Text};
    match rtype {
        // NS, MD, MF, CNAME, MB, MG, MR, PTR, NXT, DNAME, NSEC
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 30 | 39 | 47 => &[Name],
        // SOA, MINFO, RP
        6 | 14 | 17 => &[Name, Name],
        // MX, AFSDB, RT, SVCB, HTTPS
        15 | 18 | 21 | 64 | 65 => &[Fixed(2), Name],
        // PX
        26 => &[Fixed(2), Name, Name],
        // SRV
        33 => &[Fixed(6), Name],
        // NAPTR
        35 => &[Fixed(4), Text, Text, Text, Name],
        // SIG, RRSIG: the signer
        24 | 46 => &[Fixed(18), Name],
        _ => &[],
    }
}

impl<'a> Rewriter<'a> {
    fn new(src: &'a [u8]) -> Self {
        Self {
            src,
            out: Vec::with_capacity(src.len() + 64),
            cut: None,
            spans: Vec::new(),
        }
    }

    /// Drops the record at `pos`.
    fn drop_from(&mut self, pos: usize) {
        if self.cut.is_none() {
            self.out.extend_from_slice(&self.src[..pos]);
            self.cut = Some(pos);
        }
    }

    /// Keeps the record at `pos..end`, of type `rtype`.
    fn keep(&mut self, pos: usize, end: usize, rtype: u16) -> Option<()> {
        if self.cut.is_none() {
            return Some(());
        }
        let fixed = self.name(pos)?;
        // TYPE, CLASS, TTL, then an RDLENGTH set once the RDATA is written.
        self.copy(fixed, fixed + 10)?;
        let rdata_at = self.out.len();
        let mut at = fixed + 10;
        for field in rdata_fields(rtype) {
            at = match *field {
                Field::Fixed(len) => self.copy(at, at + len)?,
                Field::Text => self.copy(at, at + 1 + usize::from(*self.src.get(at)?))?,
                Field::Name => self.name(at)?,
            };
        }
        if at > end {
            return None;
        }
        self.copy(at, end)?;
        let rdlength = u16::try_from(self.out.len() - rdata_at).ok()?;
        self.out[rdata_at - 2..rdata_at].copy_from_slice(&rdlength.to_be_bytes());
        Some(())
    }

    fn finish(mut self, end: usize) -> Vec<u8> {
        if self.cut.is_none() {
            self.out.extend_from_slice(&self.src[..end]);
        }
        self.out
    }

    /// Copies the name at `pos` and returns the source offset past it. A
    /// pointer is aimed at its target's new offset; one whose labels did not
    /// all stay as they were, dropped or moved apart, is replaced by them.
    fn name(&mut self, mut pos: usize) -> Option<usize> {
        // Source offset past the name where it is written, once a pointer ends it.
        let mut end = None;
        // RFC 1035 §2.3.4 caps a name at 255 bytes, which also ends pointer loops.
        let mut len = 0usize;
        loop {
            let byte = *self.src.get(pos)?;
            match byte & 0xC0 {
                0x00 => {
                    let next = pos + 1 + usize::from(byte);
                    len += 1 + usize::from(byte);
                    if len > 255 {
                        return None;
                    }
                    self.copy_from(pos, next, end.is_none())?;
                    if byte == 0 {
                        return Some(end.unwrap_or(next));
                    }
                    pos = next;
                }
                0xC0 => {
                    let target =
                        usize::from(u16::from_be_bytes([byte & 0x3F, *self.src.get(pos + 1)?]));
                    // A pointer names an earlier occurrence (RFC 1035 §4.1.4).
                    if target >= pos {
                        return None;
                    }
                    let in_place = end.is_none();
                    let past = *end.get_or_insert(pos + 2);
                    if let Some(moved) = self.moved(target) {
                        if in_place {
                            self.span(pos, pos + 2);
                        }
                        self.out.extend_from_slice(&(0xC000 | moved).to_be_bytes());
                        return Some(past);
                    }
                    pos = target;
                }
                _ => return None,
            }
        }
    }

    /// Where the source byte at `at` sits in `out`, if a pointer can still
    /// reach it: the labels it names, up to the root or the next pointer,
    /// were all copied as is and in one piece.
    fn moved(&self, at: usize) -> Option<u16> {
        let run_end = skip_name(self.src, at)?;
        let moved = match self.cut {
            Some(cut) if run_end > cut => {
                let i = self
                    .spans
                    .partition_point(|&(start, _, _)| start <= at)
                    .checked_sub(1)?;
                let (start, end, out) = self.spans[i];
                if run_end > end {
                    return None;
                }
                out + (at - start)
            }
            _ => at,
        };
        u16::try_from(moved).ok().filter(|&m| m < 0x4000)
    }

    /// Copies `src[from..to]` as is and returns `to`.
    fn copy(&mut self, from: usize, to: usize) -> Option<usize> {
        self.copy_from(from, to, true)?;
        Some(to)
    }

    /// Copies `src[from..to]`, logging it for pointers when it is `in_place`
    /// rather than labels inlined from elsewhere.
    fn copy_from(&mut self, from: usize, to: usize, in_place: bool) -> Option<()> {
        let src = self.src;
        let bytes = src.get(from..to)?;
        if in_place {
            self.span(from, to);
        }
        self.out.extend_from_slice(bytes);
        Some(())
    }

    /// Logs that `src[from..to]` lands at the end of `out`.
    fn span(&mut self, from: usize, to: usize) {
        let at = self.out.len();
        match self.spans.last_mut() {
            Some(last) if last.1 == from && last.2 + (last.1 - last.0) == at => last.1 = to,
            _ => self.spans.push((from, to, at)),
        }
    }
}

/// Offset just past the (possibly compressed) name at `pos`.
fn skip_name(buf: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        let len = *buf.get(pos)?;
        match len & 0xC0 {
            0xC0 => return buf.get(pos + 1).map(|_| pos + 2),
            0x00 if len == 0 => return Some(pos + 1),
            0x00 => pos += 1 + usize::from(len),
            _ => return None,
        }
    }
}

/// `(type, end offset)` of the resource record at `pos`.
fn skip_rr(buf: &[u8], pos: usize) -> Option<(u16, usize)> {
    let fixed = skip_name(buf, pos)?;
    let f = buf.get(fixed..fixed + 10)?;
    let rtype = u16::from_be_bytes([f[0], f[1]]);
    let end = fixed + 10 + usize::from(u16::from_be_bytes([f[8], f[9]]));
    buf.get(..end)?;
    Some((rtype, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::opt::EdnsOption;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use std::str::FromStr;

    fn question(name: &str, qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), qtype));
        msg.to_vec().unwrap()[12..].to_vec()
    }

    fn head(rcode: Rcode) -> ResponseHead {
        ResponseHead {
            id: 0xBEEF,
            recursion_desired: true,
            authentic_data: true,
            rcode,
        }
    }

    #[test]
    fn fast_path_opt_constant_is_the_plain_edns_reply() {
        let mut written = Vec::new();
        EdnsReply {
            dnssec_ok: false,
            cookie: None,
            ede: None,
        }
        .write(&mut written, 0);
        assert_eq!(written, OPT_RECORD);
    }

    #[test]
    fn cache_hit_encoding_ignores_previous_buffer_contents() {
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        query.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        query.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]);
        let parsed = super::super::fast_path::parse_query(&query).unwrap();
        let addresses = ["192.0.2.1".parse().unwrap(), "2001:db8::1".parse().unwrap()];

        let mut clean = [0u8; RESPONSE_BUF_LEN];
        let mut dirty = [0xA5u8; RESPONSE_BUF_LEN];
        let clean_len =
            build_cache_hit_response(&parsed, &query, &addresses, 60, &mut clean).unwrap();
        let dirty_len =
            build_cache_hit_response(&parsed, &query, &addresses, 60, &mut dirty).unwrap();
        assert_eq!(&dirty[..dirty_len], &clean[..clean_len]);
        assert_eq!(
            Message::from_vec(&clean[..clean_len])
                .unwrap()
                .answers
                .len(),
            2
        );
    }

    #[test]
    fn address_response_decodes_with_header_answers_and_opt() {
        let q = question("example.com.", RecordType::AAAA);
        let addresses = ["2001:db8::1".parse().unwrap(), "192.0.2.1".parse().unwrap()];
        let cookie = [7u8; 16];
        let wire = encode_response(
            &head(Rcode::NoError),
            &q,
            1,
            ResponseBody::Addresses {
                addresses: &addresses,
                ttl: 300,
            },
            Some(&EdnsReply {
                dnssec_ok: true,
                cookie: Some(&cookie),
                ede: None,
            }),
        );

        let msg = Message::from_vec(&wire).unwrap();
        assert_eq!(msg.id, 0xBEEF);
        assert_eq!(msg.message_type, MessageType::Response);
        assert!(msg.recursion_desired && msg.recursion_available && msg.authentic_data);
        assert!(!msg.truncation);
        assert_eq!(msg.response_code, ResponseCode::NoError);
        assert_eq!(
            msg.queries[0].name(),
            &Name::from_str("example.com.").unwrap()
        );
        let answers: Vec<_> = msg
            .answers
            .iter()
            .map(|r| (r.name.clone(), r.ttl, r.data.clone()))
            .collect();
        let owner = Name::from_str("example.com.").unwrap();
        assert_eq!(
            answers,
            [
                (
                    owner.clone(),
                    300,
                    RData::AAAA("2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap().into())
                ),
                (
                    owner,
                    300,
                    RData::A("192.0.2.1".parse::<std::net::Ipv4Addr>().unwrap().into())
                ),
            ]
        );
        let edns = msg.edns.unwrap();
        assert!(edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), EDNS_UDP_PAYLOAD);
        assert!(edns
            .options()
            .as_ref()
            .iter()
            .any(|(_, o)| matches!(o, EdnsOption::Unknown(10, d) if d == &cookie)));
    }

    #[test]
    fn negative_soa_is_cacheable_for_the_block_ttl() {
        let q = question("ads.example.com.", RecordType::A);
        let wire = encode_response(
            &head(Rcode::NxDomain),
            &q,
            1,
            ResponseBody::NegativeSoa { ttl: 120 },
            None,
        );

        let msg = Message::from_vec(&wire).unwrap();
        assert_eq!(msg.response_code, ResponseCode::NXDomain);
        assert!(msg.answers.is_empty() && msg.edns.is_none());
        let soa = &msg.authorities[0];
        assert_eq!(soa.ttl, 120);
        match &soa.data {
            RData::SOA(soa) => {
                assert_eq!(soa.mname, Name::from_str("ads.example.com.").unwrap());
                assert_eq!(
                    soa.rname,
                    Name::from_str("hostmaster.ferrous-dns.invalid.").unwrap()
                );
                assert_eq!(soa.minimum, 120);
            }
            other => panic!("expected SOA, got {other:?}"),
        }
    }

    #[test]
    fn truncated_response_carries_tc_and_the_question_only() {
        let q = question("big.example.com.", RecordType::TXT);
        let msg = Message::from_vec(&encode_truncated(9, false, &q, 1)).unwrap();
        assert!(msg.truncation && !msg.recursion_desired);
        assert_eq!(msg.queries.len(), 1);
        assert!(msg.answers.is_empty() && msg.edns.is_none());
    }

    #[test]
    fn relay_replaces_the_upstream_opt_and_keeps_every_other_record() {
        let owner = Name::from_str("mail.example.com.").unwrap();
        let mut upstream = Message::new(0x1111, MessageType::Response, OpCode::Query);
        upstream.metadata.recursion_desired = true;
        upstream.metadata.recursion_available = true;
        upstream.add_query(Query::query(owner.clone(), RecordType::MX));
        upstream.add_answer(Record::from_rdata(
            owner.clone(),
            60,
            RData::MX(hickory_proto::rr::rdata::MX::new(
                10,
                Name::from_str("mx.example.com.").unwrap(),
            )),
        ));
        upstream.add_additional(Record::from_rdata(
            Name::from_str("mx.example.com.").unwrap(),
            60,
            RData::A("192.0.2.25".parse::<std::net::Ipv4Addr>().unwrap().into()),
        ));
        let mut edns = Edns::new();
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![0xAA; 16]));
        upstream.set_edns(edns);
        let upstream = upstream.to_vec().unwrap();

        let ours = [0x55u8; 16];
        let relayed = relay_with_edns(
            &upstream,
            0x2222,
            false,
            true,
            Some(&EdnsReply {
                dnssec_ok: true,
                cookie: Some(&ours),
                ede: None,
            }),
        )
        .unwrap();

        let msg = Message::from_vec(&relayed).unwrap();
        assert_eq!(msg.id, 0x2222);
        assert!(!msg.recursion_desired && msg.authentic_data);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(
            msg.additionals.len(),
            1,
            "the A glue survives, the OPT does not"
        );
        let cookies: Vec<_> = msg
            .edns
            .unwrap()
            .options()
            .as_ref()
            .iter()
            .filter_map(|(_, o)| match o {
                EdnsOption::Unknown(10, d) => Some(d.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(cookies, [ours.to_vec()]);

        let without = relay_with_edns(&upstream, 1, true, false, None).unwrap();
        assert!(Message::from_vec(&without).unwrap().edns.is_none());
    }

    #[test]
    fn relay_rejects_sections_that_overrun_the_message() {
        let mut upstream = Message::new(1, MessageType::Response, OpCode::Query);
        upstream.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::A,
        ));
        let mut wire = upstream.to_vec().unwrap();
        wire[7] = 1; // ANCOUNT claims a record the message does not hold
        assert!(relay_with_edns(&wire, 1, true, false, None).is_none());
    }

    /// RFC 6891 does not require OPT to be the last additional record. A
    /// record after it may compress its owner against another post-OPT name,
    /// and those offsets move when the OPT is cut out.
    #[test]
    fn relay_re_aims_compression_behind_a_dropped_opt() {
        let mut wire = vec![0x11, 0x11, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 3];
        wire.extend_from_slice(b"\x07example\x03com\x00\x00\x10\x00\x01"); // question @12
        wire.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]); // OPT first
        let glue = wire.len() as u8;
        wire.extend_from_slice(b"\x03ns1\xC0\x0C\x00\x01\x00\x01\x00\x00\x00\x3C\x00\x04");
        wire.extend_from_slice(&[192, 0, 2, 53]);
        wire.extend_from_slice(&[0xC0, glue, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]); // -> glue owner
        wire.extend_from_slice(&[
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x35,
        ]);
        let upstream = Message::from_vec(&wire).expect("hickory accepts the upstream message");

        let ours = EdnsReply {
            dnssec_ok: false,
            cookie: Some(&[0x55; 16]),
            ede: None,
        };
        let relayed = relay_with_edns(&wire, 1, true, false, Some(&ours)).expect("re-sectioned");
        let relayed = Message::from_vec(&relayed).expect("relayed message decodes");
        assert_eq!(relayed.additionals, upstream.additionals);
    }

    /// RDATA of an RRSIG over `covered`, signed by `example.com.`.
    fn rrsig_rdata(covered: u16) -> Vec<u8> {
        let mut rdata = covered.to_be_bytes().to_vec();
        rdata.extend_from_slice(&[
            13, 3, 0, 0, 0x0E, 0x10, 0x70, 0, 0, 0, 0x60, 0, 0, 0, 0x12, 0x34,
        ]);
        rdata.extend_from_slice(b"\x07example\x03com\x00");
        rdata.extend_from_slice(&[0xAB; 64]);
        rdata
    }

    fn rr(out: &mut Vec<u8>, owner: &[u8], rtype: u16, rdata: &[u8]) {
        out.extend_from_slice(owner);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1, 0, 0, 0, 60]);
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }

    /// A signed MX answer from a DO=1 upstream whose later records compress
    /// against the RRSIG's signer name and against each other, so cutting the
    /// RRSIG out moves or orphans their pointer targets.
    fn signed_mx_with_tangled_glue() -> Vec<u8> {
        let mut wire = vec![0x11, 0x11, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 4];
        wire.extend_from_slice(b"\x04mail\x07example\x03com\x00\x00\x0F\x00\x01"); // @12
        let exchange = wire.len() + 12 + 2;
        rr(&mut wire, &[0xC0, 12], 15, b"\x00\x0A\x03mx1\xC0\x11");
        let signer = wire.len() + 12 + 18;
        rr(&mut wire, &[0xC0, 12], TYPE_RRSIG, &rrsig_rdata(15));
        rr(&mut wire, &[0xC0, exchange as u8], 1, &[192, 0, 2, 25]);
        let mx2 = wire.len();
        // mx2.example.com, its suffix pointing into the RRSIG's signer name.
        let owner = [b"\x03mx2".as_slice(), &[0xC0, signer as u8]].concat();
        rr(
            &mut wire,
            &owner,
            28,
            &[
                0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x25,
            ],
        );
        rr(&mut wire, &[0xC0, mx2 as u8], 16, b"\x02hi");
        wire.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0x80, 0, 0, 0]);
        wire
    }

    fn types(records: &[Record]) -> Vec<RecordType> {
        records.iter().map(Record::record_type).collect()
    }

    /// RFC 4035 §3.2.1: without DO the authenticating DNSSEC RRs go, and
    /// every pointer behind them still names what it named.
    #[test]
    fn relay_strips_dnssec_records_for_a_client_without_do() {
        let wire = signed_mx_with_tangled_glue();
        let upstream = Message::from_vec(&wire).expect("hickory accepts the upstream message");
        assert_eq!(
            types(&upstream.answers),
            [RecordType::MX, RecordType::RRSIG]
        );
        let plain = EdnsReply {
            dnssec_ok: false,
            cookie: None,
            ede: None,
        };

        for edns in [Some(&plain), None] {
            let relayed = relay_with_edns(&wire, 7, true, false, edns).expect("re-sectioned");
            let relayed = Message::from_vec(&relayed).expect("relayed message decodes");
            assert_eq!(relayed.answers, upstream.answers[..1], "{edns:?}");
            assert_eq!(relayed.additionals, upstream.additionals, "{edns:?}");
            assert_eq!(
                relayed.edns.map(|e| e.flags().dnssec_ok),
                edns.map(|_| false)
            );
        }

        let validating = EdnsReply {
            dnssec_ok: true,
            ..plain
        };
        let relayed = relay_with_edns(&wire, 7, true, false, Some(&validating)).unwrap();
        let relayed = Message::from_vec(&relayed).unwrap();
        assert_eq!(relayed.answers, upstream.answers, "a DO client keeps them");
    }

    #[test]
    fn relay_keeps_dnssec_records_the_query_asked_for() {
        let mut wire = vec![0x11, 0x11, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        wire.extend_from_slice(b"\x07example\x03com\x00\x00\x2E\x00\x01"); // RRSIG query
        rr(&mut wire, &[0xC0, 12], TYPE_RRSIG, &rrsig_rdata(1));
        let relayed = relay_with_edns(&wire, 7, true, false, None).unwrap();
        assert_eq!(
            types(&Message::from_vec(&relayed).unwrap().answers),
            [RecordType::RRSIG]
        );
    }

    /// The options of `msg`'s OPT, by code.
    fn option_codes(msg: &Message) -> Vec<u16> {
        let opt = msg.edns.as_ref().expect("an OPT");
        opt.options()
            .as_ref()
            .iter()
            .map(|(code, _)| u16::from(*code))
            .collect()
    }

    /// The cached OPT's DO bit says whether the answer carries DNSSEC RRs a
    /// client without DO must not see, whatever DO the upstream echoed, and
    /// none of the upstream's options survive.
    #[test]
    fn cache_form_records_dnssec_records_in_its_do_bit_and_drops_upstream_options() {
        let signed = cache_form(&signed_mx_with_tangled_glue(), 60, 0..=u32::MAX).unwrap();
        let msg = Message::from_vec(&signed).unwrap();
        assert!(msg.edns.as_ref().unwrap().flags().dnssec_ok);
        assert_eq!(types(&msg.answers), [RecordType::MX, RecordType::RRSIG]);
        assert_eq!(option_codes(&msg), [CACHE_OPTION_CODE]);

        let mut upstream = Message::new(0x1111, MessageType::Response, OpCode::Query);
        upstream.add_query(Query::query(
            Name::from_str("example.com.").unwrap(),
            RecordType::TXT,
        ));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![0xAA; 16]));
        upstream.set_edns(edns);
        let unsigned = cache_form(&upstream.to_vec().unwrap(), 60, 0..=u32::MAX).unwrap();
        let msg = Message::from_vec(&unsigned).unwrap();
        assert!(!msg.edns.as_ref().unwrap().flags().dnssec_ok);
        assert_eq!(option_codes(&msg), [CACHE_OPTION_CODE]);
    }

    /// Serving from the cache form before any time has passed, with or
    /// without a walk, gives the bytes relaying the upstream answer would.
    #[test]
    fn relay_cached_matches_relaying_the_upstream_answer() {
        let mut upstream = Message::new(0x1111, MessageType::Response, OpCode::Query);
        upstream.metadata.recursion_desired = true;
        let owner = Name::from_str("mail.example.com.").unwrap();
        upstream.add_query(Query::query(owner.clone(), RecordType::MX));
        upstream.add_answer(Record::from_rdata(
            owner,
            60,
            RData::MX(hickory_proto::rr::rdata::MX::new(
                10,
                Name::from_str("mx.example.com.").unwrap(),
            )),
        ));
        let mut edns = Edns::new();
        edns.set_dnssec_ok(true);
        edns.options_mut()
            .insert(EdnsOption::Unknown(10, vec![0xAA; 16]));
        upstream.set_edns(edns);
        let unsigned = upstream.to_vec().unwrap();

        let cookie = [0x55; 16];
        let plain = EdnsReply {
            dnssec_ok: false,
            cookie: None,
            ede: None,
        };
        let with_cookie = EdnsReply {
            cookie: Some(&cookie),
            ..plain
        };
        for wire in [unsigned, signed_mx_with_tangled_glue()] {
            let cached = cache_form(&wire, 60, 0..=u32::MAX).unwrap();
            for edns in [None, Some(&plain), Some(&with_cookie)] {
                assert_eq!(
                    relay_cached(&cached, 9, false, edns, 60),
                    relay_with_edns(&wire, 9, false, false, edns),
                    "{edns:?}"
                );
            }
        }
    }

    /// An MX answer cached for 300 s: the MX at 300, an NS in authority at
    /// 3600 and A glue at 120, behind an upstream OPT.
    fn mx_with_authority_and_glue(signed: bool) -> Vec<u8> {
        let owner = Name::from_str("mail.example.com.").unwrap();
        let exchange = Name::from_str("mx.example.com.").unwrap();
        let mut upstream = Message::new(0x1111, MessageType::Response, OpCode::Query);
        upstream.add_query(Query::query(owner.clone(), RecordType::MX));
        upstream.add_answer(Record::from_rdata(
            owner.clone(),
            300,
            RData::MX(hickory_proto::rr::rdata::MX::new(10, exchange.clone())),
        ));
        upstream.add_authority(Record::from_rdata(
            Name::from_str("example.com.").unwrap(),
            3600,
            RData::NS(hickory_proto::rr::rdata::NS(exchange.clone())),
        ));
        upstream.add_additional(Record::from_rdata(
            exchange,
            120,
            RData::A("192.0.2.25".parse::<std::net::Ipv4Addr>().unwrap().into()),
        ));
        upstream.set_edns(Edns::new());
        let mut wire = upstream.to_vec().unwrap();
        if signed {
            // An RRSIG over the MX closes the answer section.
            let mut signature = vec![];
            rr(&mut signature, &[0xC0, 12], TYPE_RRSIG, &rrsig_rdata(15));
            // The MX's TTL, after the owner, TYPE and CLASS.
            signature[6..10].copy_from_slice(&300u32.to_be_bytes());
            let at = 12 + question("mail.example.com.", RecordType::MX).len();
            let mx_end = at + skip_rr(&wire, at).unwrap().1 - at;
            wire.splice(mx_end..mx_end, signature);
            wire[7] += 1;
        }
        wire
    }

    /// `(type, TTL)` of every record of `msg` but OPT, section by section.
    fn ttls(msg: &[u8]) -> Vec<(RecordType, u32)> {
        let msg = Message::from_vec(msg).expect("the reply decodes");
        [&msg.answers, &msg.authorities, &msg.additionals]
            .into_iter()
            .flatten()
            .map(|r| (r.record_type(), r.ttl))
            .collect()
    }

    /// RFC 1035 §3.2.1, RFC 2181 §8: a cached record's TTL counts down its
    /// time in the cache, and no record outlives the entry, as an A/AAAA hit
    /// reports it. 100 s after caching, the entry has 200 s left.
    #[test]
    fn cached_answers_count_down_every_ttl() {
        let plain = EdnsReply {
            dnssec_ok: false,
            cookie: None,
            ede: None,
        };
        let cookie = [0x55; 16];
        let with_cookie = EdnsReply {
            cookie: Some(&cookie),
            ..plain
        };
        let aged = [
            (RecordType::MX, 200),
            (RecordType::NS, 200),
            (RecordType::A, 20),
        ];
        for signed in [false, true] {
            let cached =
                cache_form(&mx_with_authority_and_glue(signed), 300, 0..=u32::MAX).unwrap();
            for edns in [None, Some(&plain), Some(&with_cookie)] {
                let reply = relay_cached(&cached, 9, false, edns, 200).unwrap();
                assert_eq!(ttls(&reply), aged, "signed {signed}, {edns:?}");
            }
            // The slow path, for a client that keeps the RRSIG.
            let validating = EdnsReply {
                dnssec_ok: true,
                ..plain
            };
            let reply = relay_aged(&cached, 9, false, false, Some(&validating), 200).unwrap();
            let mut kept = aged.to_vec();
            if signed {
                kept.insert(1, (RecordType::RRSIG, 200));
            }
            assert_eq!(ttls(&reply), kept, "signed {signed}, DO");
        }
    }

    /// RFC 8767 §4: a stale entry, and a record past its own TTL, is served
    /// with a TTL above 0: the one a stale A/AAAA hit reports.
    #[test]
    fn records_past_their_ttl_are_served_with_the_stale_ttl() {
        let cached = cache_form(&mx_with_authority_and_glue(false), 300, 0..=u32::MAX).unwrap();
        let stale = relay_cached(&cached, 9, false, None, STALE_SERVE_TTL).unwrap();
        assert!(ttls(&stale).iter().all(|&(_, ttl)| ttl == STALE_SERVE_TTL));

        // 250 s in, the glue ran out 130 s ago.
        let late = relay_cached(&cached, 9, false, None, 50).unwrap();
        assert_eq!(
            ttls(&late),
            [
                (RecordType::MX, 50),
                (RecordType::NS, 50),
                (RecordType::A, STALE_SERVE_TTL)
            ]
        );
    }

    /// The cache's TTL bounds apply to every record it stores, so an answer
    /// raised to the minimum reports what the entry has left, as A/AAAA hits
    /// do.
    #[test]
    fn cache_form_clamps_every_ttl_into_the_cache_bounds() {
        let cached = cache_form(&mx_with_authority_and_glue(false), 600, 600..=1800).unwrap();
        assert_eq!(
            ttls(&cached),
            [
                (RecordType::MX, 600),
                (RecordType::NS, 1800),
                (RecordType::A, 600)
            ]
        );
        let reply = relay_cached(&cached, 9, false, None, 500).unwrap();
        assert!(ttls(&reply).iter().all(|&(_, ttl)| ttl == 500));
    }

    /// The fast path relays nothing it cannot age: bytes that are not in
    /// cache form are left to the slow path.
    #[test]
    fn relay_cached_declines_bytes_not_in_cache_form() {
        let upstream = mx_with_authority_and_glue(false);
        assert!(relay_cached(&upstream, 9, false, None, 60).is_none());
    }

    /// RFC 6840 §5.8: the cached bytes may carry the validating upstream's
    /// AD bit, which a client without DO must not see; RD is the query's.
    #[test]
    fn relay_cached_clears_ad_and_copies_rd() {
        let mut wire = mx_with_authority_and_glue(false);
        wire[2] |= 0x01;
        wire[3] |= 0x20;
        let cached = cache_form(&wire, 300, 0..=u32::MAX).unwrap();
        for rd in [false, true] {
            let reply = relay_cached(&cached, 0x4242, rd, None, 300).unwrap();
            let msg = Message::from_vec(&reply).unwrap();
            assert_eq!(
                (msg.id, msg.recursion_desired, msg.authentic_data),
                (0x4242, rd, false)
            );
        }
    }
}
