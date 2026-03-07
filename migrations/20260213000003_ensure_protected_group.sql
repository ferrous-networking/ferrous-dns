INSERT OR IGNORE INTO groups (id, name, enabled, comment, is_default)
VALUES (
    1,
    'Protected',
    1,
    'Default group for all clients. Cannot be disabled or deleted.',
    1
);
