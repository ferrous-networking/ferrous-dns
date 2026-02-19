CREATE TABLE regex_filters (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    pattern    TEXT    NOT NULL,
    action     TEXT    NOT NULL CHECK(action IN ('allow', 'deny')),
    group_id   INTEGER NOT NULL DEFAULT 1,
    comment    TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

CREATE INDEX idx_regex_filters_enabled  ON regex_filters(enabled);
CREATE INDEX idx_regex_filters_group_id ON regex_filters(group_id);
