ALTER TABLE query_log ADD COLUMN group_id INTEGER REFERENCES groups(id);

CREATE INDEX IF NOT EXISTS idx_query_log_group
    ON query_log(group_id) WHERE group_id IS NOT NULL;
