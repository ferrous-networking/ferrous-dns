use axum::extract::State;
use axum::Json;

use crate::{
    dto::history::{ClientHistoryEntry, HistoryClientsResponse},
    errors::PiholeApiError,
    handlers::stats::{STATS_PERIOD_HOURS, TOP_ITEMS_LIMIT},
    state::PiholeAppState,
};

/// Pi-hole v6 GET /api/history/clients
///
/// Returns per-client query totals for the last 24 hours.
pub async fn get_history_clients(
    State(state): State<PiholeAppState>,
) -> Result<Json<HistoryClientsResponse>, PiholeApiError> {
    let clients = state
        .query
        .get_top_clients
        .execute(TOP_ITEMS_LIMIT, STATS_PERIOD_HOURS)
        .await?;

    let entries: Vec<ClientHistoryEntry> = clients
        .into_iter()
        .map(|(ip, hostname, total)| ClientHistoryEntry {
            name: hostname.unwrap_or_default(),
            ip,
            total,
        })
        .collect();

    Ok(Json(HistoryClientsResponse { clients: entries }))
}
