-- Config table
CREATE TABLE IF NOT EXISTS config (
                                      id INTEGER PRIMARY KEY CHECK (id = 1),
    upstream_dns TEXT NOT NULL,
    cache_enabled INTEGER NOT NULL DEFAULT 1,
    cache_ttl_seconds INTEGER NOT NULL DEFAULT 3600,
    blocklist_enabled INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

-- Query log table
CREATE TABLE IF NOT EXISTS query_log (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     domain TEXT NOT NULL,
     record_type TEXT NOT NULL,
     client_ip TEXT NOT NULL,
     blocked INTEGER NOT NULL DEFAULT 0,
     response_time_ms INTEGER,
     cache_hit INTEGER NOT NULL DEFAULT 0,
     created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Blocklist table
CREATE TABLE IF NOT EXISTS blocklist (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     domain TEXT NOT NULL UNIQUE,
     added_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_query_log_created_at ON query_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_query_log_domain ON query_log(domain);
CREATE INDEX IF NOT EXISTS idx_blocklist_domain ON blocklist(domain);
