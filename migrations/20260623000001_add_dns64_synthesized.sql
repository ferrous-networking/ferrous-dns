-- DNS64 (RFC 6147): flags query-log rows whose AAAA answer was synthesized from
-- an A record. No index: query_log is write-heavy and the flag is low-selectivity
-- (the Prometheus metric aggregates with a full scan).
ALTER TABLE query_log ADD COLUMN dns64_synthesized INTEGER NOT NULL DEFAULT 0;
