use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};

/// The client an HTTP request is attributed to, from its TCP `peer` and the
/// forwarding headers it carried.
///
/// Only a peer inside `trusted` may name another client, since any client can
/// send these headers. Each proxy appends the address it received from to
/// `X-Forwarded-For`, so the hops are walked right to left and the first one
/// that is not itself a trusted proxy is the client; hops left of it are
/// client-supplied. Without `X-Forwarded-For`, a trusted peer's `X-Real-IP`
/// is used.
///
/// `forwarded_for` holds every `X-Forwarded-For` header value in the order
/// the request carried them; `real_ip` is the `X-Real-IP` value.
pub fn forwarded_client_ip<'a>(
    peer: IpAddr,
    forwarded_for: impl DoubleEndedIterator<Item = &'a str>,
    real_ip: Option<&str>,
    trusted: &[IpNetwork],
) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    let peer = peer.to_canonical();
    if !is_trusted(peer) {
        return peer;
    }

    let mut hops = forwarded_for
        .rev()
        .flat_map(|value| value.rsplit(','))
        .peekable();
    if hops.peek().is_none() {
        return real_ip.and_then(parse_forwarded_ip).unwrap_or(peer);
    }

    let mut client = peer;
    for hop in hops {
        // A garbled hop ends the chain: whatever lies left of it is unverifiable.
        let Some(ip) = parse_forwarded_ip(hop) else {
            break;
        };
        client = ip;
        if !is_trusted(ip) {
            break;
        }
    }
    client
}

/// A forwarded address as proxies write it: a bare IP, `ip:port` or `[v6]:port`.
fn parse_forwarded_ip(text: &str) -> Option<IpAddr> {
    let text = text.trim();
    text.parse::<IpAddr>()
        .or_else(|_| text.parse::<SocketAddr>().map(|addr| addr.ip()))
        .ok()
        .map(|ip| ip.to_canonical())
}
