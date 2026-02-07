use crate::{dto::QueryResponse, state::AppState};
use axum::{extract::State, Json};
use tracing::{debug, error, instrument};

#[instrument(skip(state), name = "api_get_queries")]
pub async fn get_queries(State(state): State<AppState>) -> Json<Vec<QueryResponse>> {
    debug!("Fetching recent queries (last 24 hours)");

    match state.get_queries.execute(10000).await {
        Ok(queries) => {
            let now = chrono::Utc::now();
            let twenty_four_hours_ago = now - chrono::Duration::hours(24);

            let filtered: Vec<QueryResponse> = queries
                .into_iter()
                .filter_map(|q| {
                    if let Some(ts) = &q.timestamp {
                        if let Ok(query_time) =
                            chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S")
                        {
                            let query_time_utc =
                                chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                                    query_time,
                                    chrono::Utc,
                                );

                            if query_time_utc >= twenty_four_hours_ago {
                                return Some(QueryResponse {
                                    timestamp: q.timestamp.unwrap_or_default(),
                                    domain: q.domain,
                                    client: q.client_ip.to_string(),
                                    record_type: q.record_type.as_str().to_string(),
                                    blocked: q.blocked,
                                    response_time_ms: q.response_time_ms,
                                    cache_hit: q.cache_hit,
                                    cache_refresh: q.cache_refresh,
                                    dnssec_status: q.dnssec_status,
                                    upstream_server: q.upstream_server, // ✅ Include upstream server
                                });
                            }
                        }
                    }
                    None
                })
                .collect();

            debug!(
                count = filtered.len(),
                "Queries from last 24h retrieved successfully"
            );
            Json(filtered)
        }
        Err(e) => {
            error!(error = %e, "Failed to retrieve queries");
            Json(vec![])
        }
    }
}
