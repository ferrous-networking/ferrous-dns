CREATE TABLE IF NOT EXISTS whitelist_source_groups (
    source_id INTEGER NOT NULL REFERENCES whitelist_sources(id) ON DELETE CASCADE,
    group_id  INTEGER NOT NULL REFERENCES groups(id)            ON DELETE CASCADE,
    PRIMARY KEY (source_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_wsg_group_id ON whitelist_source_groups(group_id);
INSERT INTO whitelist_source_groups (source_id, group_id)
SELECT id, group_id FROM whitelist_sources;
