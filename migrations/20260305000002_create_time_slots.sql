CREATE TABLE IF NOT EXISTS time_slots (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL REFERENCES schedule_profiles(id) ON DELETE CASCADE,
    days       INTEGER NOT NULL DEFAULT 127
               CHECK(days >= 1 AND days <= 127),
    start_time TEXT    NOT NULL,
    end_time   TEXT    NOT NULL,
    action     TEXT    NOT NULL DEFAULT 'block_all'
               CHECK(action IN ('block_all', 'allow_all')),
    created_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_time_slots_profile ON time_slots(profile_id);
