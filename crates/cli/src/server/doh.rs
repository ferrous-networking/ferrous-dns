use axum::extract::{Query, Request};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use base64::Engine;
use ferrous_dns_infrastructure::dns::server::DnsServerHandler;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query as DnsQuery};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType as HickoryRecordType};
use hickory_proto::serialize::binary::{BinEncodable, BinEncoder};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";
const DNS_JSON_CONTENT_TYPE: &str = "application/dns-json; charset=utf-8";

#[derive(serde::Deserialize)]
pub struct DnsQueryParams {
    dns: Option<String>,
    name: Option<String>,
    #[serde(rename = "type")]
    record_type: Option<String>,
}

/// DNS-over-HTTPS handler (RFC 8484 + Google JSON format).
///
/// Wire format: `GET ?dns=<base64url>` or `POST` with `Content-Type: application/dns-message`.
/// JSON format: `GET ?name=<domain>&type=<A|AAAA|...>` with `Accept: application/dns-json`.
/// Client IP is extracted from `X-Real-IP` / `X-Forwarded-For` for correct blocklist attribution.
///
/// Injected via `Extension` to avoid a state-type conflict with the main Axum `AppState`.
pub async fn dns_query_handler(
    Extension(handler): Extension<Arc<DnsServerHandler>>,
    headers: HeaderMap,
    Query(params): Query<DnsQueryParams>,
    request: Request,
) -> Response {
    let client_ip = extract_client_ip(&headers);
    let json_response = wants_json(&headers);

    let wire = if *request.method() == Method::POST {
        match axum::body::to_bytes(request.into_body(), 65_535).await {
            Ok(b) => b.to_vec(),
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        }
    } else if json_response && params.name.is_some() {
        let name = params.name.as_deref().unwrap_or("");
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

    match handler.handle_raw_udp_fallback(&wire, client_ip).await {
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

fn extract_client_ip(headers: &HeaderMap) -> IpAddr {
    headers
        .get("x-real-ip")
        .or_else(|| headers.get("x-forwarded-for"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))
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
    edns.set_max_payload(4096);
    edns.set_version(0);

    let mut message = Message::new(fastrand::u16(..), MessageType::Query, OpCode::Query);
    message.set_recursion_desired(true);
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
        .queries()
        .iter()
        .map(|q| json!({ "name": q.name().to_string(), "type": u16::from(q.query_type()) }))
        .collect();

    let answers: Vec<Value> = msg
        .answers()
        .iter()
        .filter(|r| r.record_type() != HickoryRecordType::OPT)
        .map(|r| {
            json!({
                "name": r.name().to_string(),
                "type": u16::from(r.record_type()),
                "TTL": r.ttl(),
                "data": format_rdata(r.data()),
            })
        })
        .collect();

    let authority: Vec<Value> = msg
        .name_servers()
        .iter()
        .filter(|r| r.record_type() != HickoryRecordType::OPT)
        .map(|r| {
            json!({
                "name": r.name().to_string(),
                "type": u16::from(r.record_type()),
                "TTL": r.ttl(),
                "data": format_rdata(r.data()),
            })
        })
        .collect();

    Ok(serde_json::to_string(&json!({
        "Status": u16::from(msg.response_code()),
        "TC": msg.truncated(),
        "RD": msg.recursion_desired(),
        "RA": msg.recursion_available(),
        "AD": msg.authentic_data(),
        "CD": msg.checking_disabled(),
        "Question": questions,
        "Answer": answers,
        "Authority": authority,
    }))?)
}

fn format_rdata(data: &RData) -> String {
    match data {
        RData::A(a) => a.0.to_string(),
        RData::AAAA(aaaa) => aaaa.0.to_string(),
        RData::CNAME(name) => name.to_utf8(),
        RData::NS(name) => name.to_utf8(),
        RData::PTR(name) => name.to_utf8(),
        RData::MX(mx) => format!("{} {}", mx.preference(), mx.exchange()),
        RData::TXT(txt) => txt
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<Vec<_>>()
            .join(" "),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            soa.mname(),
            soa.rname(),
            soa.serial(),
            soa.refresh(),
            soa.retry(),
            soa.expire(),
            soa.minimum()
        ),
        _ => data.to_string(),
    }
}
