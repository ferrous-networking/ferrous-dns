CREATE TABLE IF NOT EXISTS client_subnets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subnet_cidr TEXT NOT NULL UNIQUE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    comment TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_client_subnets_group ON client_subnets(group_id);
