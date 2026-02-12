-- ============================================================================
-- Client Tracking System
-- ============================================================================
-- Stores unique network clients detected via DNS queries and ARP cache
-- Primary use case: Analytics, dashboards, and network visibility
-- Data retention: 30 days

CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

    -- Identity
    ip_address TEXT NOT NULL UNIQUE,
    mac_address TEXT,
    hostname TEXT,

    -- Tracking
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    -- Metadata
    query_count INTEGER NOT NULL DEFAULT 0,
    last_mac_update DATETIME,
    last_hostname_update DATETIME,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Indexes for Performance
-- ============================================================================

-- Primary lookup by IP (for DNS query association)
CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip_address);

-- MAC address lookup (for ARP correlation)
CREATE INDEX IF NOT EXISTS idx_clients_mac ON clients(mac_address)
WHERE mac_address IS NOT NULL;

-- Time-based queries (analytics, retention cleanup)
CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen DESC);

-- Active clients (last 24h) - partial index for dashboard
CREATE INDEX IF NOT EXISTS idx_clients_active
ON clients(last_seen DESC, query_count, hostname)
WHERE last_seen > datetime('now', '-1 day');

-- Hostname search
CREATE INDEX IF NOT EXISTS idx_clients_hostname ON clients(hostname)
WHERE hostname IS NOT NULL;

-- ============================================================================
-- Relationship with query_log
-- ============================================================================
-- NOTE: We do NOT add foreign key constraints to query_log.client_ip
-- Reason: query_log is high-throughput (batched writes), FK would slow it down
-- Instead: client_ip in query_log is implicitly linked to clients.ip_address
-- The relationship is maintained in application layer via use cases

-- For analytics, we can JOIN:
-- SELECT c.*, COUNT(q.id) as queries
-- FROM clients c
-- LEFT JOIN query_log q ON c.ip_address = q.client_ip
-- WHERE c.last_seen > datetime('now', '-7 days')
-- GROUP BY c.id;

-- ============================================================================
-- Data Retention Strategy
-- ============================================================================
-- Old clients (>30 days since last_seen) should be deleted by background job
-- Query logs are retained independently (already have their own retention)
-- No cascade delete needed since there's no FK constraint
