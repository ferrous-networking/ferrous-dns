use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::{delete, get, post, put},
    Router,
};
use ferrous_dns_domain::ScheduleAction;

use crate::{
    dto::schedule::{
        AddTimeSlotRequest, AssignProfileRequest, CreateScheduleProfileRequest,
        GroupScheduleResponse, ScheduleProfileResponse, ScheduleProfileWithSlotsResponse,
        TimeSlotResponse, UpdateScheduleProfileRequest,
    },
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/schedule-profiles", get(list_profiles))
        .route("/schedule-profiles", post(create_profile))
        .route("/schedule-profiles/{id}", get(get_profile))
        .route("/schedule-profiles/{id}", put(update_profile))
        .route("/schedule-profiles/{id}", delete(delete_profile))
        .route("/schedule-profiles/{id}/slots", post(add_slot))
        .route(
            "/schedule-profiles/{id}/slots/{slot_id}",
            delete(delete_slot),
        )
        .route("/groups/{id}/schedule", get(get_group_schedule))
        .route("/groups/{id}/schedule", put(assign_schedule))
        .route("/groups/{id}/schedule", delete(unassign_schedule))
}

async fn list_profiles(
    State(state): State<AppState>,
) -> Result<Json<Vec<ScheduleProfileResponse>>, ApiError> {
    let profiles = state.schedule.get_profiles.get_all().await?;
    Ok(Json(
        profiles
            .into_iter()
            .map(ScheduleProfileResponse::from_entity)
            .collect(),
    ))
}

async fn create_profile(
    State(state): State<AppState>,
    Json(req): Json<CreateScheduleProfileRequest>,
) -> Result<(StatusCode, Json<ScheduleProfileResponse>), ApiError> {
    let profile = state
        .schedule
        .create_profile
        .execute(req.name, req.timezone, req.comment)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(ScheduleProfileResponse::from_entity(profile)),
    ))
}

async fn get_profile(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<ScheduleProfileWithSlotsResponse>, ApiError> {
    let profile = state.schedule.get_profiles.get_by_id(id).await?;

    let slots = state.schedule.get_profiles.get_slots(id).await?;

    Ok(Json(ScheduleProfileWithSlotsResponse {
        profile: ScheduleProfileResponse::from_entity(profile),
        slots: slots
            .into_iter()
            .map(TimeSlotResponse::from_entity)
            .collect(),
    }))
}

async fn update_profile(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<UpdateScheduleProfileRequest>,
) -> Result<Json<ScheduleProfileResponse>, ApiError> {
    let profile = state
        .schedule
        .update_profile
        .execute(id, req.name, req.timezone, req.comment)
        .await?;
    Ok(Json(ScheduleProfileResponse::from_entity(profile)))
}

async fn delete_profile(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.schedule.delete_profile.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn add_slot(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<AddTimeSlotRequest>,
) -> Result<(StatusCode, Json<TimeSlotResponse>), ApiError> {
    let action = req.action.parse::<ScheduleAction>().map_err(|e| {
        ApiError(ferrous_dns_domain::DomainError::InvalidTimeSlot(
            e.to_string(),
        ))
    })?;

    let slot = state
        .schedule
        .manage_slots
        .add_slot(id, req.days, req.start_time, req.end_time, action)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(TimeSlotResponse::from_entity(slot)),
    ))
}

async fn delete_slot(
    State(state): State<AppState>,
    Path((_id, slot_id)): Path<(i64, i64)>,
) -> Result<StatusCode, ApiError> {
    state.schedule.manage_slots.delete_slot(slot_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_group_schedule(
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Result<Json<GroupScheduleResponse>, ApiError> {
    let profile_id = state
        .schedule
        .get_profiles
        .get_group_assignment(group_id)
        .await?
        .ok_or(ApiError(
            ferrous_dns_domain::DomainError::GroupHasNoSchedule(group_id),
        ))?;
    Ok(Json(GroupScheduleResponse {
        group_id,
        profile_id,
    }))
}

async fn assign_schedule(
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
    Json(req): Json<AssignProfileRequest>,
) -> Result<Json<GroupScheduleResponse>, ApiError> {
    state
        .schedule
        .assign_profile
        .assign(group_id, req.profile_id)
        .await?;
    Ok(Json(GroupScheduleResponse {
        group_id,
        profile_id: req.profile_id,
    }))
}

async fn unassign_schedule(
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.schedule.assign_profile.unassign(group_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
