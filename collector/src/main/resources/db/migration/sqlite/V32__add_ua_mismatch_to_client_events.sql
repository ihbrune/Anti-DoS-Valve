-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 32: Add ua_mismatch_count to client_events
-- ============================================================================

ALTER TABLE client_events ADD COLUMN ua_mismatch_count INTEGER;

