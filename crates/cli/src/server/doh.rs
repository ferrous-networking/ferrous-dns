use axum::extract::{ConnectInfo, Path, Query, Request};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use base64::Engine;
use ferrous_dns_application::ports::BlockFilterEnginePort;
use ferrous_dns_domain::{Config, DohId};
use ferrous_dns_infrastructure::dns::forwarding::EDNS_MAX_PAYLOAD;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query as DnsQuery};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType as HickoryRecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use ipnetwork::IpNetwork;
use serde_json::{json, Value};
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";
const DNS_JSON_CONTENT_TYPE: &str = "application/dns-json; charset=utf-8";

/// Everything a DoH request needs besides the request itself.
pub struct DohContext {
    pub handler: Arc<DnsServerHandler>,
    /// `[server].trusted_proxies`: peers allowed to name the client.
    pub trusted_proxies: Vec<IpNetwork>,
    pub block_filter: Arc<dyn BlockFilterEnginePort>,
    pub config: Arc<RwLock<Config>>,
}

#[derive(serde::Deserialize)]
pub struct DnsQueryParams {
    dns: Option<String>,
    name: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
}

/// DNS-over-HTTPS handler for `/dns-query` (RFC 8484 + Google JSON format).
///
/// Wire format: `GET ?dns=<base64url>` or `POST` with `Content-Type: application/dns-message`.
/// JSON format: `GET ?name=<domain>&type=<A|AAAA|...>` with `Accept: application/dns-json`.
/// The client is the socket peer; see [`client_ip`] for requests relayed by a
/// trusted proxy.
///
/// Injected via `Extension` to avoid a state-type conflict with the main Axum `AppState`.
pub async fn dns_query_handler(
    Extension(doh): Extension<Arc<DohContext>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
    request: Request,
) -> Response {
    handle_doh_request(doh, peer, headers, params, request, None).await
}

/// DNS-over-HTTPS handler for `/dns-query/{client_id}`.
///
/// Validates `client_id` against [`DohId::validate_client_id`] (`400 Bad Request`
/// on invalid format). When `doh_allow_unregistered_ids` is `false` (default
/// strict mode), unregistered Client IDs are also rejected with `400 Bad Request`
/// without falling back to the client IP.
pub async fn dns_query_with_id_handler(
    Extension(doh): Extension<Arc<DohContext>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
    request: Request,
) -> Response {
    handle_doh_request(doh, peer, headers, params, request, Some(client_id)).await
}

async fn handle_doh_request(
    doh: Arc<DohContext>,
    peer: SocketAddr,
    headers: HeaderMap,
    params: DnsQueryParams,
    request: Request,
    raw_client_id: Option<String>,
) -> Response {
    let doh_client_id: Option<Arc<str>> = match raw_client_id {
        Some(cid) => {
            if DohId::validate_client_id(&cid).is_err() {
                return (StatusCode::BAD_REQUEST, "Invalid DoH client ID").into_response();
            }
            if !doh.block_filter.is_doh_id_registered(&cid) {
                let allow_unregistered = doh
                    .config
                    .read()
                    .await
                    .server
                    .encrypted_dns
                    .doh_allow_unregistered_ids;
                if !allow_unregistered {
                    return (StatusCode::BAD_REQUEST, "Unregistered DoH client ID").into_response();
                }
            }
            Some(Arc::from(cid.as_str()))
        }
        None => None,
    };

    let client_ip = client_ip(peer.ip(), &headers, &doh.trusted_proxies);
    let json_response = wants_json(&headers);

    let wire = if *request.method() == Method::POST {
        match axum::body::to_bytes(request.into_body(), 65_535).await {
            Ok(b) => b.to_vec(),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else if let (true, Some(name)) = (json_response, params.name.as_deref()) {
        let qtype = params.record_type.as_deref().unwrap_or("A");
        match build_wire_query(name, qtype) {
            Ok(w) => w,
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else {
        match params.dns.as_deref() {
            Some(encoded) => match decode_base64url(encoded) {
                Ok(b) => b,
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            },
            None => return StatusCode::BAD_REQUEST.into_response(),
        }
    };

    match doh
        .handler
        .handle_raw_doh(&wire, client_ip, doh_client_id)
        .await
    {
        Some(response_bytes) if json_response => match wire_to_dns_json(&response_bytes) {
            Ok(body) => (
                StatusCode::OK,
                [(header::CONTENT_TYPE, DNS_JSON_CONTENT_TYPE)],
                body,
            )
                .into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        Some(response_bytes) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, DNS_MESSAGE_CONTENT_TYPE)],
            response_bytes,
        )
            .into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("application/dns-json"))
        .unwrap_or(false)
}

/// The client a DoH request is attributed to, and so the group policy it gets.
///
/// Only a peer inside `trusted` may name another client, since any client can
/// send these headers. Each proxy appends the address it received from to
/// `X-Forwarded-For`, so the hops are walked right to left and the first one
/// that is not itself a trusted proxy is the client; hops left of it are
/// client-supplied. Without `X-Forwarded-For`, a trusted peer's `X-Real-IP`
/// is used.
fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &[IpNetwork]) -> IpAddr {
    let is_trusted = |ip: IpAddr| trusted.iter().any(|net| net.contains(ip));
    let peer = peer.to_canonical();
    if !is_trusted(peer) {
        return peer;
    }

    let mut hops = headers
        .get_all("x-forwarded-for")
        .iter()
        .rev()
        .flat_map(|value| value.to_str().unwrap_or_default().rsplit(','))
        .peekable();
    if hops.peek().is_none() {
        return headers
            .get("x-real-ip")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_forwarded_ip)
            .unwrap_or(peer);
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

fn decode_base64url(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(input)
}

fn build_wire_query(name: &str, record_type_str: &str) -> anyhow::Result<Vec<u8>> {
    let qtype = record_type_str
        .parse::<u16>()
        .map(HickoryRecordType::from)
        .unwrap_or_else(|_| {
            HickoryRecordType::from_str(record_type_str).unwrap_or(HickoryRecordType::A)
        });

    let fqdn = if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{}.", name)
    };
    let qname = Name::from_str(&fqdn)?;

    let mut query = DnsQuery::new();
    query.set_name(qname);
    query.set_query_type(qtype);
    query.set_query_class(DNSClass::IN);

    let mut edns = Edns::new();
    edns.set_max_payload(EDNS_MAX_PAYLOAD);
    edns.set_version(0);

    let mut message = Message::new(fastrand::u16(..), MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(query);
    message.set_edns(edns);

    let mut buf = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut buf);
    message.emit(&mut encoder)?;
    Ok(buf)
}

fn wire_to_dns_json(wire: &[u8]) -> anyhow::Result<String> {
    let msg = Message::from_vec(wire)?;

    let questions: Vec<Value> = msg
        .queries
        .iter()
        .map(|q| json!({ "name": q.name().to_string(), "type": u16::from(q.query_type()) }))
        .collect();

    Ok(serde_json::to_string(&json!({
        "Status": u16::from(msg.response_code),
        "TC": msg.truncation,
        "RD": msg.recursion_desired,
        "RA": msg.recursion_available,
        "AD": msg.authentic_data,
        "CD": msg.checking_disabled,
        "Question": questions,
        "Answer": records_json(&msg.answers),
        "Authority": records_json(&msg.authorities),
    }))?)
}

fn records_json(records: &[Record]) -> Vec<Value> {
    records
        .iter()
        .filter(|r| r.record_type() != HickoryRecordType::OPT)
        .map(|r| {
            json!({
                "name": r.name.to_string(),
                "type": u16::from(r.record_type()),
                "TTL": r.ttl,
                "data": format_rdata(&r.data),
            })
        })
        .collect()
}

fn format_rdata(data: &RData) -> String {
    match data {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(aaaa) => aaaa.0.to_string(),
        RData::CNAME(name) => name.to_utf8(),
        RData::NS(name) => name.to_utf8(),
        RData::PTR(name) => name.to_utf8(),
        RData::MX(mx) => format!("{} {}", mx.preference, mx.exchange),
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<Vec<_>>()
            .join(" "),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
        ),
        _ => data.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn nets(cidrs: &[&str]) -> Vec<IpNetwork> {
        cidrs.iter().map(|cidr| cidr.parse().unwrap()).collect()
    }

    fn headers(pairs: &[(&'static str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(*name, HeaderValue::from_str(value).unwrap());
        }
        map
    }

    const LOOPBACK: [&str; 2] = ["127.0.0.0/8", "::1/128"];

    #[test]
    fn without_headers_the_client_is_the_socket_peer() {
        let none = HeaderMap::new();
        assert_eq!(
            client_ip(ip("192.168.1.50"), &none, &nets(&LOOPBACK)),
            ip("192.168.1.50")
        );
        assert_eq!(
            client_ip(ip("127.0.0.1"), &none, &nets(&LOOPBACK)),
            ip("127.0.0.1")
        );
    }

    #[test]
    fn forwarding_headers_from_an_untrusted_peer_are_ignored() {
        let spoofed = headers(&[("x-forwarded-for", "10.9.9.9"), ("x-real-ip", "10.8.8.8")]);
        assert_eq!(
            client_ip(ip("192.168.1.50"), &spoofed, &nets(&LOOPBACK)),
            ip("192.168.1.50")
        );
    }

    #[test]
    fn a_trusted_proxy_chain_resolves_to_the_right_most_untrusted_hop() {
        // 6.6.6.6 was sent by the client itself; the edge proxy appended the
        // real client, 203.0.113.7; the inner proxy appended the edge proxy.
        let relayed = headers(&[("x-forwarded-for", "6.6.6.6, 203.0.113.7, 10.0.0.2")]);
        assert_eq!(
            client_ip(
                ip("127.0.0.1"),
                &relayed,
                &nets(&["127.0.0.0/8", "10.0.0.0/8"])
            ),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn repeated_forwarded_for_headers_form_one_chain() {
        let relayed = headers(&[
            ("x-forwarded-for", "6.6.6.6, 203.0.113.7"),
            ("x-forwarded-for", "10.0.0.2"),
        ]);
        assert_eq!(
            client_ip(
                ip("127.0.0.1"),
                &relayed,
                &nets(&["127.0.0.0/8", "10.0.0.0/8"])
            ),
            ip("203.0.113.7")
        );
    }

    #[test]
    fn a_chain_of_only_trusted_hops_resolves_to_the_left_most() {
        let relayed = headers(&[("x-forwarded-for", "10.0.0.3, 10.0.0.2")]);
        assert_eq!(
            client_ip(
                ip("127.0.0.1"),
                &relayed,
                &nets(&["127.0.0.0/8", "10.0.0.0/8"])
            ),
            ip("10.0.0.3")
        );
    }

    #[test]
    fn a_garbled_hop_stops_the_walk_at_the_last_verified_address() {
        let relayed = headers(&[("x-forwarded-for", "203.0.113.7, not-an-ip, 10.0.0.2")]);
        assert_eq!(
            client_ip(
                ip("127.0.0.1"),
                &relayed,
                &nets(&["127.0.0.0/8", "10.0.0.0/8"])
            ),
            ip("10.0.0.2")
        );
    }

    #[test]
    fn a_trusted_peer_without_forwarded_for_may_use_x_real_ip() {
        let relayed = headers(&[("x-real-ip", "192.168.1.50")]);
        assert_eq!(
            client_ip(ip("127.0.0.1"), &relayed, &nets(&LOOPBACK)),
            ip("192.168.1.50")
        );
    }

    #[test]
    fn forwarded_hops_may_carry_ports_and_v4_mapped_peers_are_unmapped() {
        let relayed = headers(&[("x-forwarded-for", "203.0.113.7:51234, [2001:db8::7]:443")]);
        assert_eq!(
            client_ip(ip("::ffff:127.0.0.1"), &relayed, &nets(&LOOPBACK)),
            ip("2001:db8::7")
        );
    }
}
