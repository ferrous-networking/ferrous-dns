use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};

use crate::{
    dto::history::{ClientHistoryBucket, HistoryClient, HistoryClientsResponse},
    errors::PiholeApiError,
    handlers::stats::{bucket_centre, history_buckets, HISTORY_BUCKET_SECS},
    state::PiholeAppState,
};

/// FTL's default for `N` (`webserver.api.maxClients`).
const DEFAULT_MAX_CLIENTS: u32 = 10;

/// The series clients beyond `N` are summed into, and its name.
const OTHERS_KEY: &str = "others";
const OTHERS_NAME: &str = "other clients";

#[derive(Debug, Deserialize)]
pub struct HistoryClientsParams {
    /// Number of series to return, `others` included; 0 returns every client.
    #[serde(rename = "N")]
    n: Option<u32>,
}

/// Pi-hole v6 GET /api/history/clients
///
/// Per-client queries in the same 145 ten-minute buckets as `/history`. As
/// in FTL's history.c, the busiest clients get their own series and, when
/// they do not all fit in `N`, the rest are summed under `others`.
#[utoipa::path(
    get,
    path = "/history/clients",
    tag = "pihole:history",
    params(
        ("N" = Option<u32>, Query, description = "Number of client series (default 10, 0 for all)")
    ),
    responses(
        (status = 200, description = "Per-client query history", body = HistoryClientsResponse)
    ),
    security(("session_id" = []))
)]
pub async fn get_history_clients(
    State(state): State<PiholeAppState>,
    Query(params): Query<HistoryClientsParams>,
) -> Result<Json<HistoryClientsResponse>, PiholeApiError> {
    let max_clients = params.n.unwrap_or(DEFAULT_MAX_CLIENTS);
    let (starts, period_hours) = history_buckets();

    // One more than fits tells whether any client has to be folded.
    let fetch = match max_clients {
        0 => u32::MAX,
        n => n.saturating_add(1),
    };
    let mut ranked = state
        .query
        .get_top_clients
        .execute(fetch, period_hours)
        .await?;
    let folded = max_clients != 0 && ranked.len() > max_clients as usize;
    if folded {
        // The last of the N series is "others".
        ranked.truncate(max_clients as usize - 1);
    }

    let named: Vec<String> = ranked.iter().map(|(ip, _, _)| ip.clone()).collect();
    let activity = state
        .query
        .get_client_activity
        .execute(&named, HISTORY_BUCKET_SECS as u32, period_hours)
        .await?;

    let mut counts: HashMap<(i64, Option<&str>), u64> = HashMap::new();
    for row in &activity {
        *counts
            .entry((row.bucket, row.client_ip.as_deref()))
            .or_default() += row.count;
    }

    let mut others_total = 0;
    let history = starts
        .into_iter()
        .map(|start| {
            let mut data: BTreeMap<String, u64> = named
                .iter()
                .map(|ip| {
                    let count = counts
                        .get(&(start, Some(ip.as_str())))
                        .copied()
                        .unwrap_or(0);
                    (ip.clone(), count)
                })
                .collect();
            let others = counts.get(&(start, None)).copied().unwrap_or(0);
            others_total += others;
            data.insert(OTHERS_KEY.to_string(), others);
            ClientHistoryBucket {
                timestamp: bucket_centre(start),
                data,
            }
        })
        .collect();

    let mut clients: BTreeMap<String, HistoryClient> = ranked
        .into_iter()
        .map(|(ip, hostname, total)| {
            let name = hostname.filter(|name| !name.is_empty());
            (ip, HistoryClient { name, total })
        })
        .collect();
    if folded {
        clients.insert(
            OTHERS_KEY.to_string(),
            HistoryClient {
                name: Some(OTHERS_NAME.to_string()),
                total: others_total,
            },
        );
    }

    Ok(Json(HistoryClientsResponse { history, clients }))
}
