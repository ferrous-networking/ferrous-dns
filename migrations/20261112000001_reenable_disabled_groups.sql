-- Earlier releases ignored a group's `enabled` flag: a disabled group's clients
-- still got its rules. From this release they get the default group's instead,
-- so every disabled group is switched back on once, and an upgrade keeps
-- filtering every client as before (#382).
UPDATE groups SET enabled = 1 WHERE enabled = 0;
