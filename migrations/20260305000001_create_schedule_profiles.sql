-- ============================================================================
-- Schedule Profiles Table
-- ============================================================================
-- Stores reusable schedule profiles that define time-based DNS override rules.
-- Use case: Parental controls, work focus, IoT time restrictions.
-- Data retention: Permanent (user-managed).
--
-- A profile groups one or more TimeSlots and can be assigned to any group.
-- The scheduling engine evaluates slots every 60 seconds and writes the active
-- GroupOverride to the in-memory ScheduleStateStore.

CREATE TABLE IF NOT EXISTS schedule_profiles (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Identity
    name       TEXT    NOT NULL UNIQUE,

    -- Timezone as IANA string (e.g. "America/Sao_Paulo", "UTC", "Europe/Lisbon")
    timezone   TEXT    NOT NULL DEFAULT 'UTC',

    -- Optional description
    comment    TEXT,

    -- Timestamps (RFC3339)
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

-- ============================================================================
-- Indexes
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_schedule_profiles_name ON schedule_profiles(name);
