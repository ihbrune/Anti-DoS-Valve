-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 30: Add sample_authenticated flag to client_events for user-agent authenticity tracking
-- ============================================================================

ALTER TABLE client_events ADD COLUMN sample_authenticated BOOLEAN;

