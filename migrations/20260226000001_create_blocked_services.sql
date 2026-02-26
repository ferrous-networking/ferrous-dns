CREATE TABLE blocked_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id TEXT NOT NULL,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    UNIQUE(service_id, group_id)
);
CREATE INDEX idx_blocked_services_group ON blocked_services(group_id);
