use std::sync::Arc;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use tracing::debug;

use crate::dto::user::{CreateUserRequest, UserResponse};
use crate::errors::ApiError;
use crate::state::AppState;
use ferrous_dns_application::ports::CreateUserInput;
use ferrous_dns_domain::User;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/users", get(get_all_users))
        .route("/users", post(create_user))
        .route("/users/{id}", delete(delete_user))
}

async fn get_all_users(State(state): State<AppState>) -> Result<Json<Vec<UserResponse>>, ApiError> {
    let users = state.auth.get_users.execute().await?;
    debug!(count = users.len(), "Users retrieved");
    Ok(Json(users.into_iter().map(user_to_response).collect()))
}

async fn create_user(
    State(state): State<AppState>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserResponse>), ApiError> {
    let input = CreateUserInput {
        username: Arc::from(req.username.as_str()),
        display_name: req.display_name.map(|s| Arc::from(s.as_str())),
        password: req.password,
        role: req.role,
    };

    let user = state.auth.create_user.execute(input).await?;
    debug!(username = %user.username, "User created via API");
    Ok((StatusCode::CREATED, Json(user_to_response(user))))
}

async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.auth.delete_user.execute(id).await?;
    debug!(user_id = id, "User deleted via API");
    Ok(StatusCode::NO_CONTENT)
}

fn user_to_response(user: User) -> UserResponse {
    UserResponse {
        id: user.id,
        username: user.username.to_string(),
        display_name: user.display_name.map(|s| s.to_string()),
        role: user.role.as_str().to_string(),
        source: match user.source {
            ferrous_dns_domain::UserSource::Toml => "toml".to_string(),
            ferrous_dns_domain::UserSource::Database => "database".to_string(),
        },
        enabled: user.enabled,
        created_at: user.created_at,
        updated_at: user.updated_at,
    }
}
