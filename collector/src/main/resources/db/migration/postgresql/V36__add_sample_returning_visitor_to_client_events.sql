-- ============================================================================
-- Anti-DoS Collector Schema (PostgreSQL)
-- Version 36: Add sample_returning_visitor flag to client_events
-- ============================================================================

ALTER TABLE client_events ADD COLUMN sample_returning_visitor BOOLEAN;
