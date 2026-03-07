CREATE TABLE IF NOT EXISTS group_schedule_profiles (
    group_id   INTEGER NOT NULL PRIMARY KEY REFERENCES groups(id)            ON DELETE CASCADE,
    profile_id INTEGER NOT NULL             REFERENCES schedule_profiles(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_gsp_profile ON group_schedule_profiles(profile_id);
