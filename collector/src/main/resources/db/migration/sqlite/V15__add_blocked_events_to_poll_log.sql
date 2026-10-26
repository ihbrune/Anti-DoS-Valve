-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 15: Add blocked events ingested counter to poll_event_log
-- ============================================================================

ALTER TABLE poll_event_log ADD COLUMN blocked_events_ingested INTEGER DEFAULT 0;
