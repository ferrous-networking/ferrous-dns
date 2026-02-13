-- ============================================================================
-- Ensure Protected Group Exists
-- ============================================================================
-- This migration ensures the Protected group exists, even if the previous
-- migration failed or was interrupted. Uses INSERT OR IGNORE to be idempotent.

INSERT OR IGNORE INTO groups (id, name, enabled, comment, is_default)
VALUES (
    1,
    'Protected',
    1,
    'Default group for all clients. Cannot be disabled or deleted.',
    1
);
