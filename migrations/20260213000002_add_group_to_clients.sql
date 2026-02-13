-- ============================================================================
-- Add Group Association to Clients
-- ============================================================================
-- Adds a foreign key relationship between clients and groups
-- All clients must belong to exactly one group

-- Add group_id column with default value pointing to Protected group (id=1)
ALTER TABLE clients ADD COLUMN group_id INTEGER NOT NULL DEFAULT 1
    REFERENCES groups(id) ON DELETE RESTRICT;

-- Index for efficient group-based queries
CREATE INDEX IF NOT EXISTS idx_clients_group ON clients(group_id);

-- ============================================================================
-- Data Migration
-- ============================================================================
-- All existing clients are automatically assigned to group_id=1 (Protected)
-- due to the DEFAULT constraint. No additional UPDATE statement needed.

-- The ON DELETE RESTRICT constraint ensures that groups cannot be deleted
-- if they have assigned clients, maintaining referential integrity.
