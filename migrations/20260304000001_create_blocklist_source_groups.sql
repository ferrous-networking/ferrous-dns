CREATE TABLE IF NOT EXISTS blocklist_source_groups (
    source_id INTEGER NOT NULL REFERENCES blocklist_sources(id) ON DELETE CASCADE,
    group_id  INTEGER NOT NULL REFERENCES groups(id)            ON DELETE CASCADE,
    PRIMARY KEY (source_id, group_id)
);

CREATE INDEX IF NOT EXISTS idx_bsg_group_id ON blocklist_source_groups(group_id);
INSERT INTO blocklist_source_groups (source_id, group_id)
SELECT id, group_id FROM blocklist_sources;
