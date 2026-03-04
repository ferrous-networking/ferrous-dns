use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownScheduleAction(pub String);

impl std::fmt::Display for UnknownScheduleAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown schedule action: '{}'", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleAction {
    BlockAll,
    AllowAll,
}

impl ScheduleAction {
    pub fn to_str(self) -> &'static str {
        match self {
            ScheduleAction::BlockAll => "block_all",
            ScheduleAction::AllowAll => "allow_all",
        }
    }
}

impl std::str::FromStr for ScheduleAction {
    type Err = UnknownScheduleAction;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "block_all" => Ok(ScheduleAction::BlockAll),
            "allow_all" => Ok(ScheduleAction::AllowAll),
            _ => Err(UnknownScheduleAction(s.to_owned())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleProfile {
    pub id: Option<i64>,
    pub name: Arc<str>,
    pub timezone: Arc<str>,
    pub comment: Option<Arc<str>>,
    pub created_at: Option<Arc<str>>,
    pub updated_at: Option<Arc<str>>,
}

impl ScheduleProfile {
    pub fn validate_name(name: &str) -> Result<(), String> {
        if name.is_empty() {
            return Err("name cannot be empty".into());
        }
        if name.len() > 100 {
            return Err(format!(
                "name cannot exceed 100 characters, got {}",
                name.len()
            ));
        }
        Ok(())
    }

    pub fn validate_timezone(tz: &str) -> Result<(), String> {
        if tz.is_empty() {
            return Err("timezone cannot be empty".into());
        }
        if tz.len() > 64 {
            return Err(format!(
                "timezone cannot exceed 64 characters, got {}",
                tz.len()
            ));
        }
        Ok(())
    }

    pub fn validate_comment(comment: &Option<Arc<str>>) -> Result<(), String> {
        if let Some(c) = comment {
            if c.len() > 500 {
                return Err(format!(
                    "comment cannot exceed 500 characters, got {}",
                    c.len()
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSlot {
    pub id: Option<i64>,
    pub profile_id: i64,
    pub days: u8,
    pub start_time: Arc<str>,
    pub end_time: Arc<str>,
    pub action: ScheduleAction,
    pub created_at: Option<Arc<str>>,
}

impl TimeSlot {
    pub fn validate_days(days: u8) -> Result<(), String> {
        if days == 0 {
            return Err("at least one day must be selected".into());
        }
        if days > 127 {
            return Err(format!("days bitmask must be 1–127, got {days}"));
        }
        Ok(())
    }

    pub fn validate_time_format(time: &str) -> Result<(), String> {
        let parts: Vec<&str> = time.split(':').collect();
        if parts.len() != 2 {
            return Err(format!("time must be in HH:MM format, got '{time}'"));
        }
        let hours: u8 = parts[0]
            .parse()
            .map_err(|_| format!("invalid hours in '{time}'"))?;
        let minutes: u8 = parts[1]
            .parse()
            .map_err(|_| format!("invalid minutes in '{time}'"))?;
        if hours > 23 {
            return Err(format!("hours must be 0–23, got {hours}"));
        }
        if minutes > 59 {
            return Err(format!("minutes must be 0–59, got {minutes}"));
        }
        Ok(())
    }

    pub fn validate_time_range(start_time: &str, end_time: &str) -> Result<(), String> {
        if start_time >= end_time {
            return Err(format!(
                "start_time '{start_time}' must be before end_time '{end_time}'"
            ));
        }
        Ok(())
    }
}

pub fn evaluate_slots(
    slots: &[TimeSlot],
    weekday_bit: u8,
    now_time: &str,
) -> Option<ScheduleAction> {
    let mut found_allow = false;
    for slot in slots {
        if slot.days & weekday_bit == 0 {
            continue;
        }
        if now_time < slot.start_time.as_ref() || now_time >= slot.end_time.as_ref() {
            continue;
        }
        match slot.action {
            ScheduleAction::BlockAll => return Some(ScheduleAction::BlockAll),
            ScheduleAction::AllowAll => found_allow = true,
        }
    }
    if found_allow {
        Some(ScheduleAction::AllowAll)
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupOverride {
    BlockAll,
    AllowAll,
    TimedBypassUntil(u64),
    TimedBlockUntil(u64),
}
