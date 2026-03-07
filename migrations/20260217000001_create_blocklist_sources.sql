CREATE TABLE IF NOT EXISTS blocklist_sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,
    url         TEXT,
    group_id    INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT,
    comment     TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT 1,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_blocklist_sources_name
    ON blocklist_sources(name);
CREATE INDEX IF NOT EXISTS idx_blocklist_sources_group
    ON blocklist_sources(group_id);
CREATE INDEX IF NOT EXISTS idx_blocklist_sources_enabled
    ON blocklist_sources(enabled);
