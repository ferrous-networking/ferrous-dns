CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    comment TEXT,
    is_default BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_name ON groups(name);
CREATE UNIQUE INDEX IF NOT EXISTS idx_groups_default
ON groups(is_default) WHERE is_default = 1;

INSERT INTO groups (id, name, enabled, comment, is_default)
VALUES (
    1,
    'Protected',
    1,
    'Default group for all clients. Cannot be disabled or deleted.',
    1
);
