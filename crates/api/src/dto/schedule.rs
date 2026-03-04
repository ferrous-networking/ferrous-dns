use ferrous_dns_domain::{ScheduleProfile, TimeSlot};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct CreateScheduleProfileRequest {
    pub name: String,
    #[serde(default = "default_timezone")]
    pub timezone: String,
    pub comment: Option<String>,
}

fn default_timezone() -> String {
    "UTC".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UpdateScheduleProfileRequest {
    pub name: Option<String>,
    pub timezone: Option<String>,
    pub comment: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AddTimeSlotRequest {
    pub days: u8,
    pub start_time: String,
    pub end_time: String,
    pub action: String,
}

#[derive(Debug, Deserialize)]
pub struct AssignProfileRequest {
    pub profile_id: i64,
}

#[derive(Debug, Serialize)]
pub struct ScheduleProfileResponse {
    pub id: i64,
    pub name: String,
    pub timezone: String,
    pub comment: Option<String>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

impl ScheduleProfileResponse {
    pub fn from_entity(p: ScheduleProfile) -> Self {
        Self {
            id: p.id.unwrap_or(0),
            name: p.name.to_string(),
            timezone: p.timezone.to_string(),
            comment: p.comment.map(|c| c.to_string()),
            created_at: p.created_at.as_deref().map(String::from),
            updated_at: p.updated_at.as_deref().map(String::from),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct TimeSlotResponse {
    pub id: i64,
    pub profile_id: i64,
    pub days: u8,
    pub start_time: String,
    pub end_time: String,
    pub action: String,
    pub created_at: Option<String>,
}

impl TimeSlotResponse {
    pub fn from_entity(s: TimeSlot) -> Self {
        Self {
            id: s.id.unwrap_or(0),
            profile_id: s.profile_id,
            days: s.days,
            start_time: s.start_time.to_string(),
            end_time: s.end_time.to_string(),
            action: s.action.to_str().to_string(),
            created_at: s.created_at.as_deref().map(String::from),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ScheduleProfileWithSlotsResponse {
    #[serde(flatten)]
    pub profile: ScheduleProfileResponse,
    pub slots: Vec<TimeSlotResponse>,
}

#[derive(Debug, Serialize)]
pub struct GroupScheduleResponse {
    pub group_id: i64,
    pub profile_id: i64,
}
