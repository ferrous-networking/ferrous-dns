use axum::extract::{Path, Query, State};
use axum::Json;
use ferrous_dns_application::ports::FilterDecision;
use ferrous_dns_domain::BlockSource;
use serde::Deserialize;

use crate::{
    dto::search::{SearchResponse, SearchResult},
    errors::PiholeApiError,
    state::PiholeAppState,
};

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub client: Option<String>,
}

/// Pi-hole v6 GET /api/search/:domain
///
/// Checks whether a domain would be blocked by the current filter configuration.
pub async fn search_domain(
    State(state): State<PiholeAppState>,
    Path(domain): Path<String>,
    Query(params): Query<SearchParams>,
) -> Result<Json<SearchResponse>, PiholeApiError> {
    let group_id = if let Some(ref client_ip) = params.client {
        if let Ok(ip) = client_ip.parse::<std::net::IpAddr>() {
            state.blocking.block_filter_engine.resolve_group(ip)
        } else {
            1
        }
    } else {
        1
    };

    let decision = state.blocking.block_filter_engine.check(&domain, group_id);

    let (r#type, kind, source, blocked) = match &decision {
        FilterDecision::Block(block_source) => {
            let kind = match block_source {
                BlockSource::RegexFilter => "regex",
                _ => "exact",
            };
            ("deny", kind, format!("{block_source:?}"), true)
        }
        FilterDecision::Allow => ("allow", "exact", "allowed".to_string(), false),
    };

    let results = vec![SearchResult {
        domain,
        r#type,
        kind,
        source,
        blocked,
    }];

    Ok(Json(SearchResponse { results }))
}
