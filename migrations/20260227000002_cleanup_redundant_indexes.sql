-- clients: drop redundant/unused indexes
DROP INDEX IF EXISTS idx_clients_ip;
DROP INDEX IF EXISTS idx_clients_mac;
DROP INDEX IF EXISTS idx_clients_hostname;
DROP INDEX IF EXISTS idx_clients_last_seen;

-- blocklist/whitelist: drop redundant with UNIQUE constraints
DROP INDEX IF EXISTS idx_blocklist_domain;
DROP INDEX IF EXISTS idx_whitelist_domain;

-- groups: drop redundant with UNIQUE constraint
DROP INDEX IF EXISTS idx_groups_name;

-- blocklist_sources: drop redundant/unused
DROP INDEX IF EXISTS idx_blocklist_sources_name;
DROP INDEX IF EXISTS idx_blocklist_sources_enabled;

-- whitelist_sources: drop redundant/unused
DROP INDEX IF EXISTS idx_whitelist_sources_name;
DROP INDEX IF EXISTS idx_whitelist_sources_enabled;

-- custom_services: drop redundant with UNIQUE constraint
DROP INDEX IF EXISTS idx_custom_services_service_id;

-- clients: rebuild group index to cover ORDER BY last_seen DESC
DROP INDEX IF EXISTS idx_clients_group;
CREATE INDEX idx_clients_group ON clients(group_id, last_seen DESC);

ANALYZE;
