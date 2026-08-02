-- Resolved answer addresses (A/AAAA rdata) for the query, stored as a
-- comma-separated list and capped at the first 4 addresses to bound row size.
-- NULL for blocked rows and for record types that carry no address answer
-- (HTTPS, TXT, MX, SRV, ...). Never filtered on, so no index.
ALTER TABLE query_log ADD COLUMN answers TEXT;
