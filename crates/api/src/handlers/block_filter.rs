use axum::{extract::State, Json};
use std::net::IpAddr;
use utoipa_axum::{router::OpenApiRouter, routes};

use ferrous_dns_application::use_cases::{
    BacktestRequest, CandidateAction, DEFAULT_BACKTEST_LIMIT,
};
use ferrous_dns_domain::DomainError;

use crate::{
    dto::block_filter::{
        BacktestRequestDto, BacktestResponse, BlockFilterStatsResponse, FilterTestRequest,
        FilterTestResponse,
    },
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_block_filter_stats))
        .routes(routes!(test_domain))
        .routes(routes!(backtest_blocklists))
}

#[utoipa::path(
    get,
    path = "/block-filter/stats",
    tag = "block_filter",
    responses(
        (status = 200, description = "Block filter engine stats", body = BlockFilterStatsResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn get_block_filter_stats(
    State(state): State<AppState>,
) -> Json<BlockFilterStatsResponse> {
    let total = state.blocking.get_block_filter_stats.execute();
    Json(BlockFilterStatsResponse {
        total_blocked_domains: total,
    })
}

/// Evaluates a single domain against the static filter index, returning every
/// allow/block rule that matches (named). Dynamic runtime rules (schedule,
/// CNAME, rebinding, rate-limit, tunneling) are NOT evaluated.
#[utoipa::path(
    post,
    path = "/block-filter/test",
    tag = "block_filter",
    request_body = FilterTestRequest,
    responses(
        (status = 200, description = "Filter evaluation with named attribution", body = FilterTestResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn test_domain(
    State(state): State<AppState>,
    Json(req): Json<FilterTestRequest>,
) -> Result<Json<FilterTestResponse>, ApiError> {
    let client = req.client.as_deref().and_then(|s| s.parse::<IpAddr>().ok());
    let explanation = state
        .blocking
        .test_domain
        .execute(&req.domain, client, req.group_id);
    Ok(Json(FilterTestResponse::from(explanation)))
}

/// Simulates a candidate allow/deny ruleset (domains and/or regex) that is NOT
/// yet applied against the domains seen in recent traffic, reporting how many
/// queries it would newly block (deny) or free (allow) versus the current rules.
/// Evaluated against the static filter index only — dynamic runtime rules
/// (schedule, CNAME, rebinding, rate-limit, tunneling) are out of scope.
#[utoipa::path(
    post,
    path = "/block-filter/backtest",
    tag = "block_filter",
    request_body = BacktestRequestDto,
    responses(
        (status = 200, description = "What-if impact report", body = BacktestResponse),
        (status = 400, description = "Invalid action, empty candidate, or invalid regex"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
pub async fn backtest_blocklists(
    State(state): State<AppState>,
    Json(req): Json<BacktestRequestDto>,
) -> Result<Json<BacktestResponse>, ApiError> {
    let action = match req.action.to_ascii_lowercase().as_str() {
        "deny" => CandidateAction::Deny,
        "allow" => CandidateAction::Allow,
        other => {
            return Err(ApiError(DomainError::InvalidDomainName(format!(
                "invalid action '{other}': must be 'deny' or 'allow'"
            ))))
        }
    };
    let has_candidate = req.list.iter().any(|l| !l.trim().is_empty())
        || req.regexes.iter().any(|r| !r.trim().is_empty());
    if !has_candidate {
        return Err(ApiError(DomainError::InvalidDomainName(
            "provide at least one domain/list line or regex".to_string(),
        )));
    }
    let report = state
        .blocking
        .backtest
        .execute(BacktestRequest {
            action,
            list_lines: req.list,
            regexes: req.regexes,
            group_id: req.group_id.unwrap_or(1),
            window_hours: req.window_hours.unwrap_or(24.0),
            limit: req.limit.unwrap_or(DEFAULT_BACKTEST_LIMIT),
        })
        .await?;
    Ok(Json(BacktestResponse::from(report)))
}
