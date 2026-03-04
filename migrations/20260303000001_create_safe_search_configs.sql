CREATE TABLE safe_search_configs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id     INTEGER NOT NULL DEFAULT 1 REFERENCES groups(id),
    engine       TEXT    NOT NULL CHECK(engine IN ('google','bing','youtube','duckduckgo','yandex','brave','ecosia')),
    enabled      INTEGER NOT NULL DEFAULT 0,
    youtube_mode TEXT    NOT NULL DEFAULT 'strict' CHECK(youtube_mode IN ('strict','moderate')),
    created_at   TEXT    NOT NULL,
    updated_at   TEXT    NOT NULL,
    UNIQUE(group_id, engine)
);

CREATE INDEX idx_safe_search_group  ON safe_search_configs(group_id);
CREATE INDEX idx_safe_search_engine ON safe_search_configs(engine);