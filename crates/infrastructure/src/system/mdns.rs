//! Client names from mDNS announcements (RFC 6762).

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::{DNSClass, RData, Record};
use std::net::IpAddr;
use std::sync::Arc;

/// The longest name kept: a DNS name's limit in presentation form.
const MAX_NAME_LEN: usize = 253;
/// mDNS sets the top bit of a record's class to ask caches to flush it
/// (RFC 6762 §10.2); without hickory's `mdns` feature it stays in the class.
const CACHE_FLUSH_BIT: u16 = 0x8000;
const LOCAL_SUFFIX: &str = ".local";

/// The name the sender of one mDNS datagram announced for itself, paired
/// with each of its addresses, with `.local` dropped from the name.
///
/// Only a response counts, and in it only A and AAAA records under `local.`
/// with a TTL above 0: a TTL of 0 is a goodbye. A device can only name
/// itself, so the name is the first one with a record holding `source`,
/// and only that name's addresses count. Anything malformed yields nothing.
pub fn hostnames_from_mdns(packet: &[u8], source: IpAddr) -> Vec<(IpAddr, Arc<str>)> {
    let Ok(message) = Message::from_vec(packet) else {
        return Vec::new();
    };
    if message.metadata.message_type != MessageType::Response {
        return Vec::new();
    }

    let announced: Vec<(IpAddr, String)> = message
        .answers
        .iter()
        .chain(&message.additionals)
        .filter_map(host_address)
        .collect();
    let Some((_, own)) = announced.iter().find(|(ip, _)| *ip == source) else {
        return Vec::new();
    };
    let own: Arc<str> = Arc::from(own.as_str());

    let mut names: Vec<(IpAddr, Arc<str>)> = Vec::new();
    for (ip, name) in &announced {
        let is_new_address = !names.iter().any(|(seen, _)| seen == ip);
        if is_new_address && name.eq_ignore_ascii_case(&own) {
            names.push((*ip, Arc::clone(&own)));
        }
    }
    names
}

/// The address and host name of a live A or AAAA record under `local.`.
fn host_address(record: &Record) -> Option<(IpAddr, String)> {
    let class = u16::from(record.dns_class) & !CACHE_FLUSH_BIT;
    if record.ttl == 0 || class != u16::from(DNSClass::IN) {
        return None;
    }
    let ip = match &record.data {
        RData::A(a) => IpAddr::V4(a.0),
        RData::AAAA(aaaa) => IpAddr::V6(aaaa.0),
        _ => return None,
    };
    Some((ip, local_host_name(&record.name.to_utf8())?))
}

/// `name.local.` as `name`, when it is fit to show as a client name.
fn local_host_name(owner: &str) -> Option<String> {
    let owner = owner.strip_suffix('.').unwrap_or(owner);
    let split = owner.len().checked_sub(LOCAL_SUFFIX.len())?;
    if !owner.get(split..)?.eq_ignore_ascii_case(LOCAL_SUFFIX) {
        return None;
    }
    let name = owner.get(..split)?;
    let fit = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && !name.chars().any(|c| c.is_control() || c == '\\');
    fit.then(|| name.to_string())
}
