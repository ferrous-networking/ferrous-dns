use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use tracing::debug;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::dto::api_token::{
    ApiTokenResponse, CreateApiTokenRequest, CreatedApiTokenResponse, UpdateApiTokenRequest,
};
use crate::errors::ApiError;
use crate::state::AppState;

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(get_all_api_tokens, create_api_token))
        .routes(routes!(update_api_token, delete_api_token))
}

#[utoipa::path(
    get,
    path = "/api-tokens",
    tag = "api_tokens",
    responses(
        (status = 200, description = "All API tokens (without secrets)", body = [ApiTokenResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn get_all_api_tokens(
    State(state): State<AppState>,
) -> Result<Json<Vec<ApiTokenResponse>>, ApiError> {
    let tokens = state.auth.get_api_tokens.execute().await?;
    debug!(count = tokens.len(), "API tokens retrieved");
    Ok(Json(
        tokens
            .into_iter()
            .map(|t| ApiTokenResponse {
                id: t.id.unwrap_or(0),
                name: t.name.to_string(),
                key_prefix: t.key_prefix.to_string(),
                token: None,
                created_at: t.created_at,
                last_used_at: t.last_used_at,
            })
            .collect(),
    ))
}

#[utoipa::path(
    post,
    path = "/api-tokens",
    tag = "api_tokens",
    request_body = CreateApiTokenRequest,
    responses(
        (status = 201, description = "Token created (raw token returned only here)", body = CreatedApiTokenResponse),
        (status = 409, description = "Duplicate token name"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn create_api_token(
    State(state): State<AppState>,
    Json(req): Json<CreateApiTokenRequest>,
) -> Result<(StatusCode, Json<CreatedApiTokenResponse>), ApiError> {
    let custom = req.token.as_deref();
    let created = state
        .auth
        .create_api_token
        .execute(&req.name, custom)
        .await?;
    debug!(name = %req.name, imported = custom.is_some(), "API token created via API");
    Ok((
        StatusCode::CREATED,
        Json(CreatedApiTokenResponse {
            id: created.token.id.unwrap_or(0),
            name: created.token.name.to_string(),
            key_prefix: created.token.key_prefix.to_string(),
            token: created.raw_token,
            created_at: created.token.created_at,
        }),
    ))
}

#[utoipa::path(
    put,
    path = "/api-tokens/{id}",
    tag = "api_tokens",
    params(("id" = i64, Path, description = "Token ID")),
    request_body = UpdateApiTokenRequest,
    responses(
        (status = 200, description = "Token updated", body = ApiTokenResponse),
        (status = 404, description = "Token not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn update_api_token(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateApiTokenRequest>,
) -> Result<Json<ApiTokenResponse>, ApiError> {
    let custom = req.token.as_deref();
    let updated = state
        .auth
        .update_api_token
        .execute(id, &req.name, custom)
        .await?;
    debug!(token_id = id, name = %req.name, "API token updated via API");
    Ok(Json(ApiTokenResponse {
        id: updated.id.unwrap_or(0),
        name: updated.name.to_string(),
        key_prefix: updated.key_prefix.to_string(),
        token: updated.key_raw.map(|r| r.to_string()),
        created_at: updated.created_at,
        last_used_at: updated.last_used_at,
    }))
}

#[utoipa::path(
    delete,
    path = "/api-tokens/{id}",
    tag = "api_tokens",
    params(("id" = i64, Path, description = "Token ID")),
    responses(
        (status = 204, description = "Token deleted"),
        (status = 404, description = "Token not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_api_token(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.auth.delete_api_token.execute(id).await?;
    debug!(token_id = id, "API token deleted via API");
    Ok(StatusCode::NO_CONTENT)
}
