-- Add group_id to query_log so we can correlate queries with filter groups.
-- Optional: existing rows will have group_id = NULL.
ALTER TABLE query_log ADD COLUMN group_id INTEGER REFERENCES groups(id);

CREATE INDEX IF NOT EXISTS idx_query_log_group
    ON query_log(group_id) WHERE group_id IS NOT NULL;
