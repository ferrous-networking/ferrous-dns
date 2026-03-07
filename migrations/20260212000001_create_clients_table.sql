CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL UNIQUE,
    mac_address TEXT,
    hostname TEXT,
    first_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    query_count INTEGER NOT NULL DEFAULT 0,
    last_mac_update DATETIME,
    last_hostname_update DATETIME,

    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_clients_ip ON clients(ip_address);
CREATE INDEX IF NOT EXISTS idx_clients_mac ON clients(mac_address)
WHERE mac_address IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_clients_last_seen ON clients(last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_clients_active
ON clients(last_seen DESC, query_count, hostname)
WHERE last_seen > datetime('now', '-1 day');
CREATE INDEX IF NOT EXISTS idx_clients_hostname ON clients(hostname)
WHERE hostname IS NOT NULL;
