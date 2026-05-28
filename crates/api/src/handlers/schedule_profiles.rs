use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
};
use ferrous_dns_domain::ScheduleAction;
use utoipa_axum::{router::OpenApiRouter, routes};

use crate::{
    dto::schedule::{
        AddTimeSlotRequest, AssignProfileRequest, CreateScheduleProfileRequest,
        GroupScheduleResponse, ScheduleProfileResponse, ScheduleProfileWithSlotsResponse,
        TimeSlotResponse, UpdateScheduleProfileRequest,
    },
    errors::ApiError,
    state::AppState,
};

pub fn routes() -> OpenApiRouter<AppState> {
    OpenApiRouter::new()
        .routes(routes!(list_profiles, create_profile))
        .routes(routes!(get_profile, update_profile, delete_profile))
        .routes(routes!(add_slot))
        .routes(routes!(delete_slot))
        .routes(routes!(
            get_group_schedule,
            assign_schedule,
            unassign_schedule
        ))
}

#[utoipa::path(
    get,
    path = "/schedule-profiles",
    tag = "schedules",
    responses(
        (status = 200, description = "All schedule profiles", body = [ScheduleProfileResponse]),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    post,
    path = "/schedule-profiles",
    tag = "schedules",
    request_body = CreateScheduleProfileRequest,
    responses(
        (status = 201, description = "Profile created", body = ScheduleProfileResponse),
        (status = 409, description = "Duplicate profile name"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    get,
    path = "/schedule-profiles/{id}",
    tag = "schedules",
    params(("id" = i64, Path, description = "Profile ID")),
    responses(
        (status = 200, description = "Profile with time slots", body = ScheduleProfileWithSlotsResponse),
        (status = 404, description = "Profile not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    put,
    path = "/schedule-profiles/{id}",
    tag = "schedules",
    params(("id" = i64, Path, description = "Profile ID")),
    request_body = UpdateScheduleProfileRequest,
    responses(
        (status = 200, description = "Profile updated", body = ScheduleProfileResponse),
        (status = 404, description = "Profile not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    delete,
    path = "/schedule-profiles/{id}",
    tag = "schedules",
    params(("id" = i64, Path, description = "Profile ID")),
    responses(
        (status = 204, description = "Profile deleted"),
        (status = 404, description = "Profile not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_profile(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.schedule.delete_profile.execute(id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    post,
    path = "/schedule-profiles/{id}/slots",
    tag = "schedules",
    params(("id" = i64, Path, description = "Profile ID")),
    request_body = AddTimeSlotRequest,
    responses(
        (status = 201, description = "Time slot added", body = TimeSlotResponse),
        (status = 400, description = "Invalid time slot"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    delete,
    path = "/schedule-profiles/{id}/slots/{slot_id}",
    tag = "schedules",
    params(
        ("id" = i64, Path, description = "Profile ID"),
        ("slot_id" = i64, Path, description = "Time slot ID"),
    ),
    responses(
        (status = 204, description = "Time slot deleted"),
        (status = 404, description = "Time slot not found"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn delete_slot(
    State(state): State<AppState>,
    Path((_id, slot_id)): Path<(i64, i64)>,
) -> Result<StatusCode, ApiError> {
    state.schedule.manage_slots.delete_slot(slot_id).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[utoipa::path(
    get,
    path = "/groups/{id}/schedule",
    tag = "schedules",
    params(("id" = i64, Path, description = "Group ID")),
    responses(
        (status = 200, description = "Group's schedule assignment", body = GroupScheduleResponse),
        (status = 404, description = "Group has no schedule"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    put,
    path = "/groups/{id}/schedule",
    tag = "schedules",
    params(("id" = i64, Path, description = "Group ID")),
    request_body = AssignProfileRequest,
    responses(
        (status = 200, description = "Schedule assigned to group", body = GroupScheduleResponse),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
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

#[utoipa::path(
    delete,
    path = "/groups/{id}/schedule",
    tag = "schedules",
    params(("id" = i64, Path, description = "Group ID")),
    responses(
        (status = 204, description = "Schedule unassigned"),
    ),
    security(("session_cookie" = []), ("api_key" = [])),
)]
async fn unassign_schedule(
    State(state): State<AppState>,
    Path(group_id): Path<i64>,
) -> Result<StatusCode, ApiError> {
    state.schedule.assign_profile.unassign(group_id).await?;
    Ok(StatusCode::NO_CONTENT)
}
