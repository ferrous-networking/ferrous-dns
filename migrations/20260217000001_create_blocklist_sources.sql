-- ============================================================================
-- Blocklist Sources Table
-- ============================================================================
-- Stores named DNS blocklist sources that can be fetched from external URLs
-- Each source is associated with a group for scoped policy application
-- Data retention: Permanent (user-managed)

CREATE TABLE IF NOT EXISTS blocklist_sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Identity
    name        TEXT    NOT NULL UNIQUE,

    -- Source location (optional for manual lists)
    url         TEXT,

    -- Group association (defaults to Protected group, id=1)
    group_id    INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id) ON DELETE RESTRICT,

    -- Metadata
    comment     TEXT,
    enabled     BOOLEAN NOT NULL DEFAULT 1,

    -- Timestamps
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Indexes
-- ============================================================================

-- Name lookup (for duplicate checking)
CREATE UNIQUE INDEX IF NOT EXISTS idx_blocklist_sources_name
    ON blocklist_sources(name);

-- Group lookup (for filtering sources by group)
CREATE INDEX IF NOT EXISTS idx_blocklist_sources_group
    ON blocklist_sources(group_id);

-- Enabled lookup (for fetching active sources)
CREATE INDEX IF NOT EXISTS idx_blocklist_sources_enabled
    ON blocklist_sources(enabled);
