-- ============================================================================
-- Client Subnet Auto-Assignment System
-- ============================================================================
-- Stores CIDR ranges that automatically assign groups to matching IPs
-- When a client is detected, their IP is checked against these subnets

CREATE TABLE IF NOT EXISTS client_subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Subnet definition
    subnet_cidr TEXT NOT NULL UNIQUE,  -- e.g., "10.0.0.0/8", "192.168.1.0/24"

    -- Group assignment
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,

    -- Metadata
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Index for group lookups
CREATE INDEX IF NOT EXISTS idx_client_subnets_group ON client_subnets(group_id);

-- ============================================================================
-- IP Matching Strategy (Application Layer)
-- ============================================================================
-- SQLite doesn't have native CIDR functions, so matching happens in Rust:
-- 1. Fetch all subnets on server startup (cached in memory)
-- 2. When client detected, iterate subnets to find match
-- 3. If multiple matches, use most specific (smallest prefix length)
-- 4. Cache subnet list, invalidate on CREATE/UPDATE/DELETE
