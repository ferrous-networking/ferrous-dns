-- How the last download of a source's list went, written each time the list
-- is downloaded: 1 updated (new content, or the first copy), 2 unchanged,
-- 3 failed with the previous copy kept in use, 4 failed with no copy to use.
-- NULL means no download has been tried since this column was added. A build
-- that reuses the copy it holds leaves the value as it is.
ALTER TABLE blocklist_sources ADD COLUMN last_status INTEGER;
ALTER TABLE whitelist_sources ADD COLUMN last_status INTEGER;
