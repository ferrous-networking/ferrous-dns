-- ============================================================================
-- Groups Table
-- ============================================================================
-- Stores logical groups for organizing network clients
-- Use cases: Policy application, organization, filtering
-- Data retention: Permanent (user-managed)

CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Identity
    name TEXT NOT NULL UNIQUE,

    -- Status
    enabled BOOLEAN NOT NULL DEFAULT 1,

    -- Metadata
    comment TEXT,
    is_default BOOLEAN NOT NULL DEFAULT 0,

    -- Timestamps
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Indexes
-- ============================================================================

-- Name lookup (for duplicate checking and fast retrieval by name)
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_name ON groups(name);

-- Default group lookup (ensures only one default group exists)
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_default
ON groups(is_default) WHERE is_default = 1;

-- ============================================================================
-- Seed Default Protected Group
-- ============================================================================
-- This group is created automatically and serves as the default for all clients
-- It cannot be disabled or deleted to ensure all clients always have a group

INSERT INTO groups (id, name, enabled, comment, is_default)
VALUES (
    1,
    'Protected',
    1,
    'Default group for all clients. Cannot be disabled or deleted.',
    1
);
