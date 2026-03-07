-- ============================================================================
-- Make clients.group_id nullable
-- ============================================================================
-- Fix: clients auto-discovered by DNS were getting group_id=1 (Protected) via
-- the NOT NULL DEFAULT 1 constraint. This caused the block filter engine to
-- load every client into the per-IP cache, which was checked BEFORE the subnet
-- matcher. As a result, CIDR-based group assignments were silently ignored for
-- any client that had ever been seen.
--
-- New semantics:
--   group_id = NULL  → no explicit assignment; effective group is resolved at
--                      query time via subnet matcher → default group fallback
--   group_id = X     → user explicitly assigned this client to group X
--
-- Data migration: clients that only have group_id=1 because of the old DEFAULT
-- are reset to NULL. Clients explicitly assigned to a non-default group keep
-- their assignment. Clients explicitly assigned to Protected (id=1) are also
-- reset — there is no way to distinguish them from the auto-assigned ones, and
-- with NULL they will still fall back to Protected through the default group.

PRAGMA foreign_keys = OFF;

CREATE TABLE clients_new (
    id                   INTEGER  PRIMARY KEY AUTOINCREMENT,
    ip_address           TEXT     NOT NULL UNIQUE,
    mac_address          TEXT,
    hostname             TEXT,
    first_seen           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen            DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    query_count          INTEGER  NOT NULL DEFAULT 0,
    last_mac_update      DATETIME,
    last_hostname_update DATETIME,
    created_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at           DATETIME DEFAULT CURRENT_TIMESTAMP,
    group_id             INTEGER  REFERENCES groups(id) ON DELETE SET NULL
);

INSERT INTO clients_new
    SELECT
        id,
        ip_address,
        mac_address,
        hostname,
        first_seen,
        last_seen,
        query_count,
        last_mac_update,
        last_hostname_update,
        created_at,
        updated_at,
        CASE WHEN group_id = 1 THEN NULL ELSE group_id END
    FROM clients;

DROP TABLE clients;

ALTER TABLE clients_new RENAME TO clients;

CREATE INDEX idx_clients_ip
    ON clients(ip_address, hostname);

CREATE INDEX idx_clients_group
    ON clients(group_id, last_seen DESC);

CREATE INDEX idx_clients_stats_coverage
    ON clients(last_seen DESC, mac_address, hostname);

PRAGMA foreign_keys = ON;
