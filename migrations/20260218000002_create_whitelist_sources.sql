CREATE TABLE IF NOT EXISTS whitelist_sources (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT    NOT NULL UNIQUE,
    url        TEXT,
    group_id   INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id),
    comment    TEXT,
    enabled    BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_whitelist_sources_name     ON whitelist_sources(name);
CREATE INDEX IF NOT EXISTS idx_whitelist_sources_group_id ON whitelist_sources(group_id);
CREATE INDEX IF NOT EXISTS idx_whitelist_sources_enabled  ON whitelist_sources(enabled);
