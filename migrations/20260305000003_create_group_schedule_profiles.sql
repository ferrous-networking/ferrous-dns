-- ============================================================================
-- Group Schedule Profiles Table
-- ============================================================================
-- Associates a ScheduleProfile to a Group (one profile per group maximum).
-- Use case: Apply time-based DNS override rules to all clients in a group.
-- Data retention: Cascade-deleted when either the group or the profile is removed.
--
-- Design notes:
--   group_id is the PRIMARY KEY → enforces at most one profile per group.
--   Deleting a profile removes this row; the group reverts to no schedule.
--   Deleting a group removes this row; the profile remains available.

CREATE TABLE IF NOT EXISTS group_schedule_profiles (
    group_id   INTEGER NOT NULL PRIMARY KEY REFERENCES groups(id)            ON DELETE CASCADE,
    profile_id INTEGER NOT NULL             REFERENCES schedule_profiles(id) ON DELETE CASCADE
);

-- ============================================================================
-- Indexes
-- ============================================================================

-- Allows quick lookup of all groups assigned to a given profile
CREATE INDEX IF NOT EXISTS idx_gsp_profile ON group_schedule_profiles(profile_id);
