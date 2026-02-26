CREATE TABLE custom_services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category_name TEXT NOT NULL DEFAULT 'Custom',
    domains TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_custom_services_service_id ON custom_services(service_id);
