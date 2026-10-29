-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 19: Add request sample metadata to client_events for blocked incident forensics
-- ============================================================================

ALTER TABLE client_events ADD COLUMN sample_method VARCHAR(16);
ALTER TABLE client_events ADD COLUMN sample_uri VARCHAR(256);
ALTER TABLE client_events ADD COLUMN sample_user_agent VARCHAR(128);

