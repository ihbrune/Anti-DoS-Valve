-- ============================================================================
-- Anti-DoS Collector Schema (SQLite)
-- Version 10: Add distinct_clients column to client_events for subnet cardinality
-- ============================================================================

ALTER TABLE client_events ADD COLUMN distinct_clients INTEGER NOT NULL DEFAULT 1;
