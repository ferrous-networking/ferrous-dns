CREATE TABLE managed_domains (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    domain     TEXT    NOT NULL,
    action     TEXT    NOT NULL CHECK(action IN ('allow', 'deny')),
    group_id   INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id),
    comment    TEXT,
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT    NOT NULL,
    updated_at TEXT    NOT NULL
);
