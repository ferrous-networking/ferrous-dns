CREATE TABLE IF NOT EXISTS schedule_profiles (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    timezone   TEXT    NOT NULL DEFAULT 'UTC',
    comment    TEXT,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_schedule_profiles_name ON schedule_profiles(name);
