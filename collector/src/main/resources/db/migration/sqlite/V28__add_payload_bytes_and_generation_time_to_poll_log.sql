-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 28: Add payload bytes and server generation time to poll_event_log
-- ============================================================================

ALTER TABLE poll_event_log ADD COLUMN payload_bytes BIGINT DEFAULT 0;
ALTER TABLE poll_event_log ADD COLUMN server_generation_ms INTEGER DEFAULT 0;

