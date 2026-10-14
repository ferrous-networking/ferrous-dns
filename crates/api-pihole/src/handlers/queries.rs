use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use ferrous_dns_application::ports::{PageAt, PagedQueryResult};
use ferrous_dns_application::use_cases::PagedQueryInput;
use ferrous_dns_domain::{
    DnssecStatus, DnssecStatusFilter, DomainError, RecordType, ReplyFilter, ReplyKind,
};
use serde::Deserialize;

use crate::{
    dto::queries::{
        dnssec_name, forward_address, map_query_status, query_type_name, PiholeClientRef,
        PiholeEde, PiholeQueryEntry, PiholeReply, QueriesResponse, QuerySuggestions,
        SuggestionsResponse, FTL_DNSSEC_STATUSES, FTL_QUERY_STATUSES, FTL_QUERY_TYPES,
        FTL_REPLY_TYPES,
    },
    errors::{pihole_error_response, PiholeApiError},
    handlers::stats::{upstream_servers, MAX_PERIOD_HOURS, STATS_PERIOD_HOURS},
    state::PiholeAppState,
    timestamp::parse_unix_epoch,
};

/// FTL's default page length.
const DEFAULT_LENGTH: u32 = 100;

/// FTL's `API_QUERIES_MAX_ROWS`: the most rows one reply carries, also when
/// every row is asked for.
const MAX_LENGTH: u32 = 10_000;

/// FTL's default for the `count` of `/queries/suggestions`.
const DEFAULT_SUGGESTIONS_COUNT: u32 = 30;

/// Query parameters of `GET /queries`, as FTL's `api_queries` reads them.
///
/// `domain`, `client_ip` and `client_name` match as substrings, with any `*`
/// at their ends dropped, where FTL matches exactly or by wildcard; the three
/// share one client filter, so only the first given applies.
#[derive(Debug, Deserialize)]
pub struct QueryParams {
    from: Option<f64>,
    until: Option<f64>,
    domain: Option<String>,
    client_ip: Option<String>,
    client_name: Option<String>,
    /// Ferrous's earlier name for `client_ip`, still honoured.
    client: Option<String>,
    upstream: Option<String>,
    #[serde(rename = "type")]
    query_type: Option<String>,
    status: Option<String>,
    reply: Option<String>,
    dnssec: Option<String>,
    disk: Option<bool>,
    length: Option<i64>,
    start: Option<u32>,
    cursor: Option<i64>,
    draw: Option<i64>,
}

/// A failed `/queries` request.
pub enum QueriesError {
    /// A parameter FTL rejects: its message, with the offending value as hint.
    BadRequest {
        message: &'static str,
        hint: String,
    },
    Domain(DomainError),
}

impl From<DomainError> for QueriesError {
    fn from(err: DomainError) -> Self {
        Self::Domain(err)
    }
}

impl IntoResponse for QueriesError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest { message, hint } => {
                pihole_error_response(StatusCode::BAD_REQUEST, "bad_request", message, Some(&hint))
            }
            Self::Domain(err) => PiholeApiError(err).into_response(),
        }
    }
}

/// Which logged queries the FTL filters select, in the query log's terms.
#[derive(Debug, Default)]
struct Selection {
    category: Option<&'static str>,
    record_type: Option<&'static str>,
    /// For `OTHER`: every type FTL names, left out.
    excluded_record_types: Vec<RecordType>,
    reply: Option<ReplyKind>,
    dnssec: Option<DnssecStatusFilter>,
    upstream: Option<String>,
    /// A filter no query Ferrous logs can match, such as a status it never
    /// produces.
    is_empty: bool,
}

impl Selection {
    /// Narrows to the queries of both the current category and `category`.
    fn restrict_category(&mut self, category: &'static str) {
        self.category = match (self.category, category) {
            (None, new) => Some(new),
            (Some(current), new) if current == new => Some(current),
            (Some("allowed"), narrower @ ("cache" | "upstream"))
            | (Some(narrower @ ("cache" | "upstream")), "allowed") => Some(narrower),
            (current, _) => {
                self.is_empty = true;
                current
            }
        };
    }
}

/// The FTL name in `names` that `value` spells, ignoring case, or FTL's 400.
fn ftl_name(
    names: &'static [&'static str],
    value: &str,
    message: &'static str,
) -> Result<&'static str, QueriesError> {
    names
        .iter()
        .find(|name| name.eq_ignore_ascii_case(value))
        .copied()
        .ok_or_else(|| QueriesError::BadRequest {
            message,
            hint: value.to_string(),
        })
}

/// A string parameter FTL reads: absent when empty.
fn given(value: &Option<String>) -> Option<&str> {
    value.as_deref().filter(|v| !v.is_empty())
}

/// `status`: the blocked statuses select every block, since the log keeps
/// no filter per block source; a `CACHE` filter misses answers from local
/// configuration. Statuses Ferrous never reports select nothing.
fn select_status(selection: &mut Selection, status: &str) -> Result<(), QueriesError> {
    match ftl_name(&FTL_QUERY_STATUSES, status, "Requested status is invalid")? {
        "GRAVITY" | "REGEX" | "DENYLIST" | "GRAVITY_CNAME" => {
            selection.restrict_category("blocked")
        }
        "FORWARDED" => selection.restrict_category("upstream"),
        "CACHE" => selection.restrict_category("cache"),
        _ => selection.is_empty = true,
    }
    Ok(())
}

/// `type`: `OTHER` is every type outside FTL's list, as FTL counts them
/// (dnsmasq_interface.c); Ferrous never logs `ANY`.
fn select_type(selection: &mut Selection, query_type: &str) -> Result<(), QueriesError> {
    match ftl_name(&FTL_QUERY_TYPES, query_type, "Requested type is invalid")? {
        "OTHER" => {
            selection.excluded_record_types = FTL_QUERY_TYPES
                .iter()
                .filter_map(|name| name.parse().ok())
                .collect();
        }
        "ANY" => selection.is_empty = true,
        name => selection.record_type = Some(name),
    }
    Ok(())
}

/// `reply`: FTL's reply types Ferrous never logs (`DOMAIN`, `RRNAME`,
/// `NOTIMP`, `DNSSEC`, `BLOB`) select nothing.
fn select_reply(selection: &mut Selection, reply: &str) -> Result<(), QueriesError> {
    match ftl_name(&FTL_REPLY_TYPES, reply, "Requested reply is invalid")?.parse() {
        Ok(kind) => selection.reply = Some(kind),
        Err(_) => selection.is_empty = true,
    }
    Ok(())
}

/// `dnssec`: `ABANDONED` is Ferrous's `Indeterminate`, `UNKNOWN` a query
/// never validated; Ferrous never reports `TRUNCATED`.
fn select_dnssec(selection: &mut Selection, dnssec: &str) -> Result<(), QueriesError> {
    selection.dnssec = match ftl_name(&FTL_DNSSEC_STATUSES, dnssec, "Requested dnssec is invalid")?
    {
        "SECURE" => Some(DnssecStatusFilter::Is(DnssecStatus::Secure)),
        "INSECURE" => Some(DnssecStatusFilter::Is(DnssecStatus::Insecure)),
        "BOGUS" => Some(DnssecStatusFilter::Is(DnssecStatus::Bogus)),
        "ABANDONED" => Some(DnssecStatusFilter::Is(DnssecStatus::Indeterminate)),
        "UNKNOWN" => Some(DnssecStatusFilter::NotValidated),
        _ => {
            selection.is_empty = true;
            None
        }
    };
    Ok(())
}

/// `upstream`: FTL's pseudo-upstreams select a category; an `ip#port` (with
/// FTL's optional ` (name)` suffix) selects the server it names among those
/// that answered in the window, the busiest when several share it; anything
/// else is matched as the server URL Ferrous records.
async fn select_upstream(
    state: &PiholeAppState,
    selection: &mut Selection,
    upstream: &str,
    period: f32,
) -> Result<(), QueriesError> {
    let upstream = upstream.split(' ').next().unwrap_or(upstream);
    match upstream {
        "blocklist" => selection.restrict_category("blocked"),
        "cache" => selection.restrict_category("cache"),
        "permitted" => selection.restrict_category("allowed"),
        address if address.contains('#') => {
            let stats = state.query.get_stats.execute(period).await?;
            match upstream_servers(&stats)
                .into_iter()
                .find(|(server, _)| forward_address(server) == address)
            {
                Some((server, _)) => selection.upstream = Some(server.to_string()),
                None => selection.is_empty = true,
            }
        }
        server => selection.upstream = Some(server.to_string()),
    }
    Ok(())
}

/// Hours from the Unix time `from` until now.
fn hours_since(from: f64) -> f32 {
    let hours = (Utc::now().timestamp() as f64 - from) / 3_600.0;
    (hours as f32).clamp(0.0, MAX_PERIOD_HOURS)
}

/// Pi-hole v6 GET /api/queries
///
/// Pages through the query log newest first. The first page pins `cursor` to
/// the newest query; sending it back with `start` pages through that snapshot,
/// unshifted by queries logged since. `length` 0 or below asks for every
/// query, capped at 10000 as FTL caps it. `until` is exclusive, as in
/// queries.c. A blocked query's reply type, for `reply` as in each entry,
/// follows the current block mode.
#[utoipa::path(
    get,
    path = "/queries",
    tag = "pihole:queries",
    params(
        ("from" = Option<f64>, Query, description = "Only queries at or after this Unix time"),
        ("until" = Option<f64>, Query, description = "Only queries before this Unix time"),
        ("domain" = Option<String>, Query, description = "Filter by domain (substring)"),
        ("client_ip" = Option<String>, Query, description = "Filter by client IP (substring)"),
        ("client_name" = Option<String>, Query, description = "Filter by client name (substring)"),
        ("client" = Option<String>, Query, description = "Alias of client_ip"),
        ("upstream" = Option<String>, Query, description = "ip#port, blocklist, cache or permitted"),
        ("type" = Option<String>, Query, description = "FTL query type"),
        ("status" = Option<String>, Query, description = "FTL query status"),
        ("reply" = Option<String>, Query, description = "FTL reply type"),
        ("dnssec" = Option<String>, Query, description = "FTL DNSSEC status"),
        ("disk" = Option<bool>, Query, description = "Read the whole stored log"),
        ("length" = Option<i64>, Query, description = "Page size (default 100, <= 0 for all)"),
        ("start" = Option<u32>, Query, description = "Rows to skip"),
        ("cursor" = Option<i64>, Query, description = "Snapshot cursor from an earlier page"),
        ("draw" = Option<i64>, Query, description = "DataTables draw counter")
    ),
    responses(
        (status = 200, description = "Paginated query log", body = QueriesResponse),
        (status = 400, description = "Invalid filter value or cursor")
    ),
    security(("session_id" = []))
)]
pub async fn get_queries(
    State(state): State<PiholeAppState>,
    Query(params): Query<QueryParams>,
) -> Result<Json<QueriesResponse>, QueriesError> {
    let disk = params.disk.unwrap_or(false);
    let period = match params.from {
        Some(from) if from.is_finite() => hours_since(from),
        _ if disk => MAX_PERIOD_HOURS,
        _ => STATS_PERIOD_HOURS,
    };

    let mut selection = Selection::default();
    if let Some(query_type) = given(&params.query_type) {
        select_type(&mut selection, query_type)?;
    }
    if let Some(status) = given(&params.status) {
        select_status(&mut selection, status)?;
    }
    if let Some(reply) = given(&params.reply) {
        select_reply(&mut selection, reply)?;
    }
    if let Some(dnssec) = given(&params.dnssec) {
        select_dnssec(&mut selection, dnssec)?;
    }
    if let Some(upstream) = given(&params.upstream) {
        select_upstream(&state, &mut selection, upstream, period).await?;
    }
    let domain = given(&params.domain).map(|d| d.trim_matches('*'));
    let client = given(&params.client_ip)
        .or(given(&params.client_name))
        .or(given(&params.client))
        .map(|c| c.trim_matches('*'));
    let is_filtering = params.from.is_some()
        || params.until.is_some()
        || domain.is_some()
        || client.is_some()
        || [
            &params.upstream,
            &params.query_type,
            &params.status,
            &params.reply,
            &params.dnssec,
        ]
        .into_iter()
        .any(|p| given(p).is_some());

    let storage = state
        .query
        .get_query_log_storage
        .execute(STATS_PERIOD_HOURS)
        .await?;
    let newest_id = match params.cursor {
        None => storage.newest_id,
        Some(cursor) if (0..=storage.newest_id).contains(&cursor) => cursor,
        Some(_) => {
            return Err(QueriesError::BadRequest {
                message: "Requested cursor is invalid",
                hint: "Cursor larger than largest database index".to_string(),
            })
        }
    };
    let length = match params.length {
        None => DEFAULT_LENGTH,
        Some(length) if length <= 0 => MAX_LENGTH,
        Some(length) => u32::try_from(length).map_or(MAX_LENGTH, |l| l.min(MAX_LENGTH)),
    };

    let block_mode = state.system.config.read().await.blocking.block_mode;
    let page = if selection.is_empty {
        PagedQueryResult {
            queries: Vec::new(),
            records_total: 0,
            records_filtered: 0,
            next_cursor: None,
        }
    } else {
        let input = PagedQueryInput {
            limit: length,
            page: PageAt::Snapshot {
                newest_id,
                offset: params.start.unwrap_or(0),
            },
            period_hours: period,
            domain,
            category: selection.category,
            client,
            record_type: selection.record_type,
            upstream: selection.upstream.as_deref(),
            dnssec_status: selection.dnssec,
            until: params
                .until
                .filter(|until| until.is_finite())
                .map(|until| until as i64),
            excluded_record_types: selection.excluded_record_types.clone(),
            reply: selection.reply.map(|kind| ReplyFilter { kind, block_mode }),
            ..Default::default()
        };
        state.query.get_recent_queries.execute_paged(&input).await?
    };

    let queries = page
        .queries
        .into_iter()
        .map(|q| PiholeQueryEntry {
            id: q.id.unwrap_or(0),
            time: q
                .timestamp
                .as_deref()
                .and_then(parse_unix_epoch)
                .map(|ts| ts as f64)
                .unwrap_or(0.0),
            r#type: query_type_name(q.record_type).into_owned(),
            domain: q.domain.to_string(),
            client: PiholeClientRef {
                ip: q.client_ip.to_string(),
                name: q
                    .client_hostname
                    .as_ref()
                    .map(|h| h.to_string())
                    .filter(|h| !h.is_empty()),
            },
            status: map_query_status(&q),
            dnssec: dnssec_name(q.dnssec_status),
            reply: PiholeReply {
                r#type: q.reply_kind(block_mode).as_str(),
                time: q
                    .response_time_us
                    .map(|t| t as f64 / 1_000_000.0)
                    .unwrap_or(0.0),
            },
            upstream: q.upstream_server.as_deref().map(forward_address),
            cname: None,
            list_id: None,
            ede: PiholeEde {
                code: -1,
                text: None,
            },
        })
        .collect();

    let records_total = if disk {
        storage.stored_queries
    } else {
        storage.recent_queries
    };
    Ok(Json(QueriesResponse {
        queries,
        cursor: newest_id,
        records_total,
        records_filtered: if is_filtering {
            page.records_filtered
        } else {
            records_total
        },
        draw: params.draw.unwrap_or(0),
        earliest_timestamp: storage.recent_earliest,
        earliest_timestamp_disk: storage.stored_earliest,
    }))
}

#[derive(Debug, Deserialize)]
pub struct SuggestionsParams {
    count: Option<u32>,
}

/// Pi-hole v6 GET /api/queries/suggestions
///
/// The values the query log can be filtered by: the top `count` domains
/// (allowed, then blocked) and clients of the last 24 hours, the upstreams
/// that answered in it, and every FTL type, status, reply and DNSSEC name.
#[utoipa::path(
    get,
    path = "/queries/suggestions",
    tag = "pihole:queries",
    params(
        ("count" = Option<u32>, Query, description = "Domains and clients per list (default 30)")
    ),
    responses(
        (status = 200, description = "Filter suggestions for queries UI", body = SuggestionsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_suggestions(
    State(state): State<PiholeAppState>,
    Query(params): Query<SuggestionsParams>,
) -> Result<Json<SuggestionsResponse>, PiholeApiError> {
    let count = params.count.unwrap_or(DEFAULT_SUGGESTIONS_COUNT);
    let query = &state.query;
    let (allowed, blocked, clients, stats) = tokio::join!(
        query
            .get_top_allowed_domains
            .execute(count, STATS_PERIOD_HOURS),
        query
            .get_top_blocked_domains
            .execute(count, STATS_PERIOD_HOURS),
        query.get_top_clients.execute(count, STATS_PERIOD_HOURS),
        query.get_stats.execute(STATS_PERIOD_HOURS),
    );
    let (clients, stats) = (clients?, stats?);

    let mut domain: Vec<String> = allowed?.into_iter().map(|(d, _)| d).collect();
    for (blocked_domain, _) in blocked? {
        if !domain.contains(&blocked_domain) {
            domain.push(blocked_domain);
        }
    }

    let mut client_name: Vec<String> = Vec::new();
    for name in clients.iter().filter_map(|(_, name, _)| name.as_ref()) {
        if !name.is_empty() && !client_name.contains(name) {
            client_name.push(name.clone());
        }
    }

    let mut upstream = vec!["blocklist".to_owned(), "cache".to_owned()];
    for (server, _) in upstream_servers(&stats) {
        let address = forward_address(server);
        if !upstream.contains(&address) {
            upstream.push(address);
        }
    }
    upstream.push("permitted".to_owned());
    let names = |list: &[&str]| list.iter().map(|s| (*s).to_owned()).collect();

    Ok(Json(SuggestionsResponse {
        suggestions: QuerySuggestions {
            domain,
            client_ip: clients.into_iter().map(|(ip, _, _)| ip).collect(),
            client_name,
            upstream,
            r#type: names(&FTL_QUERY_TYPES),
            status: names(&FTL_QUERY_STATUSES),
            reply: names(&FTL_REPLY_TYPES),
            dnssec: names(&FTL_DNSSEC_STATUSES),
        },
    }))
}
