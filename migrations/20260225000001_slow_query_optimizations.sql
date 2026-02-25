DROP INDEX IF EXISTS idx_query_log_source_created;
CREATE INDEX idx_query_log_source_created
    ON query_log(query_source, created_at DESC, blocked);

DROP INDEX IF EXISTS idx_clients_ip;
CREATE INDEX idx_clients_ip
    ON clients(ip_address, hostname);

ANALYZE query_log;
ANALYZE clients;
