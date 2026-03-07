DROP INDEX IF EXISTS idx_clients_ip;
DROP INDEX IF EXISTS idx_clients_mac;
DROP INDEX IF EXISTS idx_clients_hostname;
DROP INDEX IF EXISTS idx_clients_last_seen;
DROP INDEX IF EXISTS idx_blocklist_domain;
DROP INDEX IF EXISTS idx_whitelist_domain;
DROP INDEX IF EXISTS idx_groups_name;
DROP INDEX IF EXISTS idx_blocklist_sources_name;
DROP INDEX IF EXISTS idx_blocklist_sources_enabled;
DROP INDEX IF EXISTS idx_whitelist_sources_name;
DROP INDEX IF EXISTS idx_whitelist_sources_enabled;
DROP INDEX IF EXISTS idx_custom_services_service_id;
DROP INDEX IF EXISTS idx_clients_group;
CREATE INDEX idx_clients_group ON clients(group_id, last_seen DESC);

ANALYZE;
