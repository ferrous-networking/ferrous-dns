-- idx_safe_search_engine on safe_search_configs(engine) is redundant:
-- queries always filter by (group_id, engine) together, which is covered by
-- the UNIQUE(group_id, engine) index already present on the table.
DROP INDEX IF EXISTS idx_safe_search_engine;
