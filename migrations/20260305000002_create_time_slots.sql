-- ============================================================================
-- Time Slots Table
-- ============================================================================
-- Stores individual time windows within a ScheduleProfile.
-- Use case: Define when block_all or allow_all applies for a group.
-- Data retention: Cascade-deleted with parent schedule_profile.
--
-- Each slot defines:
--   days       - bitmask of active days: bit0=Mon, bit1=Tue, ..., bit6=Sun
--                0b0011111 (31)  = Mon–Fri
--                0b1100000 (96)  = Sat–Sun
--                0b1111111 (127) = every day
--   start_time - inclusive start "HH:MM" (00:00–23:59)
--   end_time   - exclusive end   "HH:MM" (start_time < end_time, no midnight-spanning)
--   action     - 'block_all' blocks all DNS for the group during this window
--                'allow_all' removes any block override during this window
--
-- Conflict resolution (evaluated in evaluator.rs):
--   If any active slot has action='block_all', the group is blocked.
--   All active slots must have action='allow_all' for the group to be allowed.

CREATE TABLE IF NOT EXISTS time_slots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Parent profile (CASCADE delete keeps referential integrity)
    profile_id INTEGER NOT NULL REFERENCES schedule_profiles(id) ON DELETE CASCADE,

    -- Day bitmask: 1–127, bit0=Mon..bit6=Sun
    days       INTEGER NOT NULL DEFAULT 127
               CHECK(days >= 1 AND days <= 127),

    -- Time range
    start_time TEXT    NOT NULL,  -- "HH:MM"
    end_time   TEXT    NOT NULL,  -- "HH:MM"

    -- Override action
    action     TEXT    NOT NULL DEFAULT 'block_all'
               CHECK(action IN ('block_all', 'allow_all')),

    -- Timestamp (RFC3339)
    created_at TEXT    NOT NULL
);

-- ============================================================================
-- Indexes
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_time_slots_profile ON time_slots(profile_id);
