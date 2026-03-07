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
