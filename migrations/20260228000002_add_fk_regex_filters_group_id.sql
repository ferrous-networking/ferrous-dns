-- Add FK constraint on regex_filters.group_id → groups(id)
-- SQLite does not support ALTER TABLE ADD CONSTRAINT, so we recreate the table.

CREATE TABLE regex_filters_new (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    pattern    TEXT    NOT NULL,
    action     TEXT    NOT NULL CHECK(action IN ('allow', 'deny')),
    group_id   INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT,
    comment    TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);

INSERT INTO regex_filters_new SELECT * FROM regex_filters;

DROP TABLE regex_filters;

ALTER TABLE regex_filters_new RENAME TO regex_filters;

CREATE INDEX idx_regex_filters_enabled  ON regex_filters(enabled);
CREATE INDEX idx_regex_filters_group_id ON regex_filters(group_id);
